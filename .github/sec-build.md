```yaml
╭ [0]  ╭ Target: nmaguiar/gcutils:build (alpine 3.25.0_alpha20260805) 
│      ├ Class : os-pkgs 
│      ╰ Type  : alpine 
├ [1]  ╭ Target  : Java 
│      ├ Class   : lang-pkgs 
│      ├ Type    : jar 
│      ╰ Packages 
├ [2]  ╭ Target  : Node.js 
│      ├ Class   : lang-pkgs 
│      ├ Type    : node-pkg 
│      ╰ Packages 
├ [3]  ╭ Target  : Python 
│      ├ Class   : lang-pkgs 
│      ├ Type    : python-pkg 
│      ╰ Packages 
├ [4]  ╭ Target         : usr/bin/prometheus 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.58.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.58.0 
│                        │     │                  ╰ UID : 6b32b088100b2775 
│                        │     ├ InstalledVersion: v0.58.0 
│                        │     ├ FixedVersion    : 0.58.1-0.20261009181718-2f1f834330b2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:a53093099379cc3a55a7205dfe9f6313303e9fecbd9a288130a79
│                        │     │                   209457467be 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References                                           
│                        │                        ────────────────────────────────────
│                        │                        https://go.dev/issue/44226          
│                        │                        https://go.dev/issue/81227          
│                        │                        https://pkg.go.dev/vuln/GO-2026-5932
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                                                      
│                        │     │                  ──────────────────────────────────────────────
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : eb5d80b2cf98517f 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:7dc0656b19d9f6b371f5893735f940a7fba7b975033cffc4d90fb
│                        │     │                   f527bad33d6 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [2] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : eb5d80b2cf98517f 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:6a3bd5f0159b4b3aeef1e9791e256dec84183e4f63056490f9995
│                        │     │                   235689d496d 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [3] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : 7fc18fed89e8a080 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:0acd2ca770db06e1a64596d8e18962238d9ca71c9f2ee6f606787
│                              │                   4074917074c 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [5]  ╭ Target         : usr/bin/promtool 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.58.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.58.0 
│                        │     │                  ╰ UID : 6d0ce5627be3d2e1 
│                        │     ├ InstalledVersion: v0.58.0 
│                        │     ├ FixedVersion    : 0.58.1-0.20261009181718-2f1f834330b2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:dc0b552a16a2257eefbf2de5fb8a7582ac34ac2996de637a4ae82
│                        │     │                   995959a8e05 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References                                           
│                        │                        ────────────────────────────────────
│                        │                        https://go.dev/issue/44226          
│                        │                        https://go.dev/issue/81227          
│                        │                        https://pkg.go.dev/vuln/GO-2026-5932
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : dc957dfc4333dd87 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:fd3a411f6f18937aed48c72304e241769a01f22886ca45d31f71b
│                        │     │                   d79d1918d32 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [2] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : dc957dfc4333dd87 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:8e35d8c69ca618e21404b3180dbd0d6cfa9098ac1110574df2f71
│                        │     │                   19be7b86ba5 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [3] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : 7c38b8addeabcb18 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:280bef4b24b88a573dd3e29b4d093d61016f97119b5807b4ab0a4
│                              │                   4aca573f2f9 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  CWE-820                                                      
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [6]  ╭ Target         : usr/share/grafana/bin/grafana 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-128085 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-q7gw-24fr-5p69
│                        │     ├ PkgID           : go.opentelemetry.io/otel/sdk/log@v0.22.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/sdk/log 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk/log@v0.22.0 
│                        │     │                  ╰ UID : 5466be96f2101af0 
│                        │     ├ InstalledVersion: v0.22.0 
│                        │     ├ FixedVersion    : 1.47.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:83dd575480ff24ad4e9ce10f0a5c9c7ba7e919e4f2050c24d34fe
│                        │     │                   d3ac9cd21ee 
│                        │     ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │     │                   go.opentelemetry.io/otel/sdk/log:
│                        │     │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │     │                   Service via attribute truncation bypass using Unicode
│                        │     │                   replacement characters 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │     │                   version 1.35.0 until version 1.47.0, the
│                        │     │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │     │                   truncation paths in sdk/internal/attrnorm,
│                        │     │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │     │                   valid U+FFFD replacement characters. This is a distinct
│                        │     │                   incomplete-fix defect in the replacement truncation code
│                        │     │                   introduced by the remediation for CVE-2026-81869. Values
│                        │     │                   composed of or dominated by those characters can therefore
│                        │     │                   exceed the configured character and memory bound in span,
│                        │     │                   log-record, and auto-instrumentation trace attributes.
│                        │     │                   Attacker-controlled telemetry attributes can increase
│                        │     │                   retained memory and pipeline pressure, while confidentiality
│                        │     │                    and integrity are not affected. This issue is fixed in
│                        │     │                   version 1.47.0. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-135
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:L 
│                        │     │                  │        ╰ V3Score : 5.3 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-128085       
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-128085              
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/commit/017
│                        │     │                  b08c7f1018b619991aaf6b2299d4beb9da1d3                        
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/log/v1.47.0                                           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/v1.47.0                                               
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/trace/v1.47.0                                             
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/security/a
│                        │     │                  dvisories/GHSA-q7gw-24fr-5p69                                
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085             
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-128085             
│                        │     ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │     ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [1] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.58.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.58.0 
│                        │     │                  ╰ UID : 753efda111a30074 
│                        │     ├ InstalledVersion: v0.58.0 
│                        │     ├ FixedVersion    : 0.58.1-0.20261009181718-2f1f834330b2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:b25cef74b0f9ddddb606412269a910b360809261101590a9cb4ae
│                        │     │                   9cfae033b80 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References                                           
│                        │                        ────────────────────────────────────
│                        │                        https://go.dev/issue/44226          
│                        │                        https://go.dev/issue/81227          
│                        │                        https://pkg.go.dev/vuln/GO-2026-5932
│                        ╰ [2] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : cdd84a85e329d895 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:905077d610044d1b5d8bc41590e84477ac894aec0c7f4d9c9b355
│                              │                   14ec36db759 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [7]  ╭ Target         : usr/share/grafana/data/plugins-bundled/cloudwatch/gpx_grafana_cloudwatch_datasource_l
│      │                  inux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.58.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.58.0 
│                        │     │                  ╰ UID : a33afad965b0ff9b 
│                        │     ├ InstalledVersion: v0.58.0 
│                        │     ├ FixedVersion    : 0.58.1-0.20261009181718-2f1f834330b2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:4ac54ec6cba872edb46da03342f7afa7f1c2bb806c73fce87e6d5
│                        │     │                   6594b0aef08 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References                                           
│                        │                        ────────────────────────────────────
│                        │                        https://go.dev/issue/44226          
│                        │                        https://go.dev/issue/81227          
│                        │                        https://pkg.go.dev/vuln/GO-2026-5932
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : e8794dc5c4b80575 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:27b50f0ac4fc666c9d45acf8a513945da61866e6c61bacd7157bf
│                        │     │                   06d55f4f0af 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [2] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : e8794dc5c4b80575 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:c9444053a7b00aa4181d1da1ab30deea2fe81b232d21af14dc485
│                        │     │                   7a640d79ed2 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [3] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : 1dd1a71c78bd7fc2 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:1b16bc2dc85b0efa95d6c1f9e2245542f1a0b351a35ac7acc64a6
│                              │                   1239e718848 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [8]  ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_dataso
│      │                  urce_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.58.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.58.0 
│                        │     │                  ╰ UID : 2ad0afe666c0d14d 
│                        │     ├ InstalledVersion: v0.58.0 
│                        │     ├ FixedVersion    : 0.58.1-0.20261009181718-2f1f834330b2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:19d4d92612d2706adb14c42b4969641155e320c5e067fb22ce95c
│                        │     │                   4058ae61325 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References                                           
│                        │                        ────────────────────────────────────
│                        │                        https://go.dev/issue/44226          
│                        │                        https://go.dev/issue/81227          
│                        │                        https://pkg.go.dev/vuln/GO-2026-5932
│                        ╰ [1] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : 42c697bd1adfd28c 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:aa48ac0eb250b7c23c22d9d851b286e8fd25fc6aa2e887b500c6d
│                              │                   f04068733cf 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [9]  ╭ Target         : usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/gpx_grafana_post
│      │                  gresql_datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : 9aa87ba83b545ff 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:861c39f4f8fa342884ab6abeb545743bbd7614757d2c2864548d8
│                        │     │                   9fa70f56490 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : 9aa87ba83b545ff 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:b4615863c2d99c46d6580ecd6383e51c3ed730c58ac443fc0e190
│                        │     │                   c5e9ea7c1e9 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [2] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : 78ff9acc83d4ee90 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:11aae7dd505658510de916d96b12c985e1e87f3eee0fa6a6cef4f
│                              │                   4811eed236e 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [10] ╭ Target         : usr/share/grafana/data/plugins-bundled/grafana-pyroscope-datasource/gpx_grafana-pyros
│      │                  cope-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : e52d55aeb6c9d2ae 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:1eff37eb7b5bdaaed3f418e98eb774b79b5d89eafa67eb6cc8763
│                        │     │                   028ec9fbbad 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : e52d55aeb6c9d2ae 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:5a364374475d2229ab48668cffd9f1399532af2193026969c228e
│                        │     │                   a402fede6c3 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [2] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : 85ec2cf042eec6bd 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:c8285da9ab28fecded6c987c551e4f13d29c9c711e95efa14f495
│                              │                   123c61cd962 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [11] ╭ Target         : usr/share/grafana/data/plugins-bundled/influxdb/gpx_grafana_influxdb_datasource_linux
│      │                  _amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-128085 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-q7gw-24fr-5p69
│                        │     ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.45.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/sdk 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.45.0 
│                        │     │                  ╰ UID : 2a08a90bdbbb5529 
│                        │     ├ InstalledVersion: v1.45.0 
│                        │     ├ FixedVersion    : 1.47.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:cef641adfd5234000882fb88dc851fb4ed71ad04863f0a057be61
│                        │     │                   4b6db86556f 
│                        │     ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │     │                   go.opentelemetry.io/otel/sdk/log:
│                        │     │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │     │                   Service via attribute truncation bypass using Unicode
│                        │     │                   replacement characters 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │     │                   version 1.35.0 until version 1.47.0, the
│                        │     │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │     │                   truncation paths in sdk/internal/attrnorm,
│                        │     │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │     │                   valid U+FFFD replacement characters. This is a distinct
│                        │     │                   incomplete-fix defect in the replacement truncation code
│                        │     │                   introduced by the remediation for CVE-2026-81869. Values
│                        │     │                   composed of or dominated by those characters can therefore
│                        │     │                   exceed the configured character and memory bound in span,
│                        │     │                   log-record, and auto-instrumentation trace attributes.
│                        │     │                   Attacker-controlled telemetry attributes can increase
│                        │     │                   retained memory and pipeline pressure, while confidentiality
│                        │     │                    and integrity are not affected. This issue is fixed in
│                        │     │                   version 1.47.0. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-135
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:L 
│                        │     │                  │        ╰ V3Score : 5.3 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-128085       
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-128085              
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/commit/017
│                        │     │                  b08c7f1018b619991aaf6b2299d4beb9da1d3                        
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/log/v1.47.0                                           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/v1.47.0                                               
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/trace/v1.47.0                                             
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/security/a
│                        │     │                  dvisories/GHSA-q7gw-24fr-5p69                                
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085             
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-128085             
│                        │     ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │     ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-128085 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-q7gw-24fr-5p69
│                        │     ├ PkgID           : go.opentelemetry.io/otel/trace@v1.45.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/trace 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/trace@v1.45.0 
│                        │     │                  ╰ UID : 2c7bf2200a42df2f 
│                        │     ├ InstalledVersion: v1.45.0 
│                        │     ├ FixedVersion    : 1.47.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:5bb8758266c71aa88504181165f25a3ba01ff66eb0a731007100c
│                        │     │                   aca6b18d1ec 
│                        │     ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │     │                   go.opentelemetry.io/otel/sdk/log:
│                        │     │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │     │                   Service via attribute truncation bypass using Unicode
│                        │     │                   replacement characters 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │     │                   version 1.35.0 until version 1.47.0, the
│                        │     │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │     │                   truncation paths in sdk/internal/attrnorm,
│                        │     │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │     │                   valid U+FFFD replacement characters. This is a distinct
│                        │     │                   incomplete-fix defect in the replacement truncation code
│                        │     │                   introduced by the remediation for CVE-2026-81869. Values
│                        │     │                   composed of or dominated by those characters can therefore
│                        │     │                   exceed the configured character and memory bound in span,
│                        │     │                   log-record, and auto-instrumentation trace attributes.
│                        │     │                   Attacker-controlled telemetry attributes can increase
│                        │     │                   retained memory and pipeline pressure, while confidentiality
│                        │     │                    and integrity are not affected. This issue is fixed in
│                        │     │                   version 1.47.0. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-135
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:L 
│                        │     │                  │        ╰ V3Score : 5.3 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-128085       
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-128085              
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/commit/017
│                        │     │                  b08c7f1018b619991aaf6b2299d4beb9da1d3                        
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/log/v1.47.0                                           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/v1.47.0                                               
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/trace/v1.47.0                                             
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/security/a
│                        │     │                  dvisories/GHSA-q7gw-24fr-5p69                                
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085             
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-128085             
│                        │     ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │     ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [2] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.60.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.60.0 
│                        │     │                  ╰ UID : 131841ace774f5f4 
│                        │     ├ InstalledVersion: v0.60.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:95c28022390e27125c0ee1bb56e8190e27a60418b4acc90eba4f6
│                        │     │                   5775a3fca92 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661        
│                        │     │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                        │     │                  https://go.dev/cl/849365                                     
│                        │     │                  https://go.dev/issue/82224                                   
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs    
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661              
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                         
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661              
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [3] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.60.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.60.0 
│                        │     │                  ╰ UID : 131841ace774f5f4 
│                        │     ├ InstalledVersion: v0.60.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:2aa97abc4ebf7bd08507f22d599392d4b5ca0649233769d82cdad
│                        │     │                   073c4ef3d8a 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [4] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : f9d23ae3a2c57249 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:f11771f051431367493cde531d011a70a6f53a52c089be82ad865
│                              │                   712543a9c6b 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [12] ╭ Target         : usr/share/grafana/data/plugins-bundled/jaeger/gpx_grafana-jaeger-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : 5174e7607322715 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:b501840e4a8877238d44d1f426a1035fa09418612cecacbdb3414
│                        │     │                   024ea229e93 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : 5174e7607322715 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:d47e2538c84f0344d0323d90fcb2ff76eb1f62c593f430885ab07
│                        │     │                   f51369c3ab2 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [2] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : f1bce7629babe35a 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:d7f3aba01d3e3c005f83d2ea3df8101f30d1b8faea6e53029bc1f
│                              │                   11b0263acd0 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [13] ╭ Target         : usr/share/grafana/data/plugins-bundled/loki/gpx_grafana-loki-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-128085 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-q7gw-24fr-5p69
│                        │     ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.46.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/sdk 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.46.0 
│                        │     │                  ╰ UID : 30fc3f559e3b600a 
│                        │     ├ InstalledVersion: v1.46.0 
│                        │     ├ FixedVersion    : 1.47.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:088230cc07d13342439cf2ffb78f9dcb6ad9cacd4253c6f089255
│                        │     │                   aa11bcd8585 
│                        │     ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │     │                   go.opentelemetry.io/otel/sdk/log:
│                        │     │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │     │                   Service via attribute truncation bypass using Unicode
│                        │     │                   replacement characters 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │     │                   version 1.35.0 until version 1.47.0, the
│                        │     │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │     │                   truncation paths in sdk/internal/attrnorm,
│                        │     │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │     │                   valid U+FFFD replacement characters. This is a distinct
│                        │     │                   incomplete-fix defect in the replacement truncation code
│                        │     │                   introduced by the remediation for CVE-2026-81869. Values
│                        │     │                   composed of or dominated by those characters can therefore
│                        │     │                   exceed the configured character and memory bound in span,
│                        │     │                   log-record, and auto-instrumentation trace attributes.
│                        │     │                   Attacker-controlled telemetry attributes can increase
│                        │     │                   retained memory and pipeline pressure, while confidentiality
│                        │     │                    and integrity are not affected. This issue is fixed in
│                        │     │                   version 1.47.0. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-135
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:L 
│                        │     │                  │        ╰ V3Score : 5.3 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-128085       
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-128085              
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/commit/017
│                        │     │                  b08c7f1018b619991aaf6b2299d4beb9da1d3                        
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/log/v1.47.0                                           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/v1.47.0                                               
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/trace/v1.47.0                                             
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/security/a
│                        │     │                  dvisories/GHSA-q7gw-24fr-5p69                                
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085             
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-128085             
│                        │     ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │     ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-128085 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-q7gw-24fr-5p69
│                        │     ├ PkgID           : go.opentelemetry.io/otel/sdk/log@v0.22.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/sdk/log 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk/log@v0.22.0 
│                        │     │                  ╰ UID : 4fae24f31f0571bd 
│                        │     ├ InstalledVersion: v0.22.0 
│                        │     ├ FixedVersion    : 1.47.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:e40cc9ecc0ae2163291b9f972fc5cd4b5d3cc87e4c064a4582385
│                        │     │                   a182c2c9b83 
│                        │     ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │     │                   go.opentelemetry.io/otel/sdk/log:
│                        │     │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │     │                   Service via attribute truncation bypass using Unicode
│                        │     │                   replacement characters 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │     │                   version 1.35.0 until version 1.47.0, the
│                        │     │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │     │                   truncation paths in sdk/internal/attrnorm,
│                        │     │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │     │                   valid U+FFFD replacement characters. This is a distinct
│                        │     │                   incomplete-fix defect in the replacement truncation code
│                        │     │                   introduced by the remediation for CVE-2026-81869. Values
│                        │     │                   composed of or dominated by those characters can therefore
│                        │     │                   exceed the configured character and memory bound in span,
│                        │     │                   log-record, and auto-instrumentation trace attributes.
│                        │     │                   Attacker-controlled telemetry attributes can increase
│                        │     │                   retained memory and pipeline pressure, while confidentiality
│                        │     │                    and integrity are not affected. This issue is fixed in
│                        │     │                   version 1.47.0. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-135
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:L 
│                        │     │                  │        ╰ V3Score : 5.3 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-128085       
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-128085              
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/commit/017
│                        │     │                  b08c7f1018b619991aaf6b2299d4beb9da1d3                        
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/log/v1.47.0                                           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/v1.47.0                                               
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/trace/v1.47.0                                             
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/security/a
│                        │     │                  dvisories/GHSA-q7gw-24fr-5p69                                
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085             
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-128085             
│                        │     ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │     ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [2] ╭ VulnerabilityID : CVE-2026-128085 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-q7gw-24fr-5p69
│                        │     ├ PkgID           : go.opentelemetry.io/otel/trace@v1.46.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/trace 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/trace@v1.46.0 
│                        │     │                  ╰ UID : aa7f1f2a5258ef71 
│                        │     ├ InstalledVersion: v1.46.0 
│                        │     ├ FixedVersion    : 1.47.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:22ca9a643e3471b4b55dab62cf7c2ad74f251880d63f04461d543
│                        │     │                   ba7f9b8d1ae 
│                        │     ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │     │                   go.opentelemetry.io/otel/sdk/log:
│                        │     │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │     │                   Service via attribute truncation bypass using Unicode
│                        │     │                   replacement characters 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │     │                   version 1.35.0 until version 1.47.0, the
│                        │     │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │     │                   truncation paths in sdk/internal/attrnorm,
│                        │     │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │     │                   valid U+FFFD replacement characters. This is a distinct
│                        │     │                   incomplete-fix defect in the replacement truncation code
│                        │     │                   introduced by the remediation for CVE-2026-81869. Values
│                        │     │                   composed of or dominated by those characters can therefore
│                        │     │                   exceed the configured character and memory bound in span,
│                        │     │                   log-record, and auto-instrumentation trace attributes.
│                        │     │                   Attacker-controlled telemetry attributes can increase
│                        │     │                   retained memory and pipeline pressure, while confidentiality
│                        │     │                    and integrity are not affected. This issue is fixed in
│                        │     │                   version 1.47.0. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-135
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:L 
│                        │     │                  │        ╰ V3Score : 5.3 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-128085       
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-128085              
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/commit/017
│                        │     │                  b08c7f1018b619991aaf6b2299d4beb9da1d3                        
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/log/v1.47.0                                           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/v1.47.0                                               
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/trace/v1.47.0                                             
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/security/a
│                        │     │                  dvisories/GHSA-q7gw-24fr-5p69                                
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085             
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-128085             
│                        │     ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │     ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [3] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.57.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.57.0 
│                        │     │                  ╰ UID : ff0a2e98d6cfef4 
│                        │     ├ InstalledVersion: v0.57.0 
│                        │     ├ FixedVersion    : 0.58.1-0.20261009181718-2f1f834330b2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:79cf5f1494c033925b72ae50e6209a7395ff34280eae75378bf56
│                        │     │                   6151dcab751 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References                                           
│                        │                        ────────────────────────────────────
│                        │                        https://go.dev/issue/44226          
│                        │                        https://go.dev/issue/81227          
│                        │                        https://pkg.go.dev/vuln/GO-2026-5932
│                        ├ [4] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.60.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.60.0 
│                        │     │                  ╰ UID : 894be65ed25fd40d 
│                        │     ├ InstalledVersion: v0.60.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:8141dcad5124feafc8dbd62c2644d375846e50d50b44052e55937
│                        │     │                   c6f649b9e6a 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [5] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.60.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.60.0 
│                        │     │                  ╰ UID : 894be65ed25fd40d 
│                        │     ├ InstalledVersion: v0.60.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:d727f86ac034a47f0d276ffa32c497195e3f32196aebb62bf8b99
│                        │     │                   1ea55434615 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [6] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : f0e003c1978537b4 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:a5d1c137ace4ffc96275fd127631fc9d63a921182867edc534257
│                              │                   31265d2dda5 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [14] ╭ Target         : usr/share/grafana/data/plugins-bundled/mssql/gpx_grafana-mssql-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.58.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.58.0 
│                        │     │                  ╰ UID : 86ae196907fc8c19 
│                        │     ├ InstalledVersion: v0.58.0 
│                        │     ├ FixedVersion    : 0.58.1-0.20261009181718-2f1f834330b2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:40995257143e22d6b49e3327b4120486bd3863d68248765867889
│                        │     │                   3693216e2ce 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References                                           
│                        │                        ────────────────────────────────────
│                        │                        https://go.dev/issue/44226          
│                        │                        https://go.dev/issue/81227          
│                        │                        https://pkg.go.dev/vuln/GO-2026-5932
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : f5329dac1bd58c33 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:e9aae247e2f7518f8f3189d11b56cb932120a726fc22a92660260
│                        │     │                   da4533114de 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [2] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : f5329dac1bd58c33 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:42b619552250e2d3d0243ab5129654199dd87e7e7b7b1b7c7fb7b
│                        │     │                   9064c7d02bb 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [3] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : ca9811e69a206d44 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:22d9749a9e88e7f2b12390df74523a62ce456f5e5d5835baee255
│                              │                   0a2b1075a61 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [15] ╭ Target         : usr/share/grafana/data/plugins-bundled/mysql/gpx_grafana-mysql-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-128085 
│                        │      ├ VendorIDs                           
│                        │      │                  ───────────────────
│                        │      │                  GHSA-q7gw-24fr-5p69
│                        │      ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.46.0 
│                        │      ├ PkgName         : go.opentelemetry.io/otel/sdk 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.46.0 
│                        │      │                  ╰ UID : 6159d5f72ef9f2d6 
│                        │      ├ InstalledVersion: v1.46.0 
│                        │      ├ FixedVersion    : 1.47.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ SeveritySource  : ghsa 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │      ├ DataSource       ╭ ID  : ghsa 
│                        │      │                  ├ Name: GitHub Security Advisory Go 
│                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+
│                        │      │                          ecosystem%3Ago 
│                        │      ├ Fingerprint     : sha256:30b0ceea567bd2287aeecfadee287f901c18bf6e285a4981aac1
│                        │      │                   0fce1e8d7296 
│                        │      ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │      │                   go.opentelemetry.io/otel/sdk/log:
│                        │      │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │      │                    Service via attribute truncation bypass using Unicode
│                        │      │                   replacement characters 
│                        │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │      │                    From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │      │                   version 1.35.0 until version 1.47.0, the
│                        │      │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │      │                    truncation paths in sdk/internal/attrnorm,
│                        │      │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │      │                   valid U+FFFD replacement characters. This is a distinct
│                        │      │                   incomplete-fix defect in the replacement truncation code
│                        │      │                   introduced by the remediation for CVE-2026-81869. Values
│                        │      │                   composed of or dominated by those characters can therefore
│                        │      │                   exceed the configured character and memory bound in span,
│                        │      │                   log-record, and auto-instrumentation trace attributes.
│                        │      │                   Attacker-controlled telemetry attributes can increase
│                        │      │                   retained memory and pipeline pressure, while
│                        │      │                   confidentiality and integrity are not affected. This issue
│                        │      │                   is fixed in version 1.47.0. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-135
│                        │      │                  CWE-770
│                        │      ├ VendorSeverity   ╭ ghsa  : 2 
│                        │      │                  ╰ redhat: 2 
│                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                        │      │                  │        │           N/A:L 
│                        │      │                  │        ╰ V3Score : 5.3 
│                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                        │      │                           │           N/A:L 
│                        │      │                           ╰ V3Score : 5.3 
│                        │      ├ References                                                                   
│                        │      │                  ────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-128085      
│                        │      │                  https://advisory.echohq.com/cve/CVE-2026-128085             
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go          
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/commit/01
│                        │      │                  7b08c7f1018b619991aaf6b2299d4beb9da1d3                      
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/releases/
│                        │      │                  tag/sdk/log/v1.47.0                                         
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/releases/
│                        │      │                  tag/sdk/v1.47.0                                             
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/releases/
│                        │      │                  tag/trace/v1.47.0                                           
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/security/
│                        │      │                  advisories/GHSA-q7gw-24fr-5p69                              
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085            
│                        │      │                                                                              
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-128085            
│                        │      ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │      ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [1]  ╭ VulnerabilityID : CVE-2026-128085 
│                        │      ├ VendorIDs                           
│                        │      │                  ───────────────────
│                        │      │                  GHSA-q7gw-24fr-5p69
│                        │      ├ PkgID           : go.opentelemetry.io/otel/trace@v1.46.0 
│                        │      ├ PkgName         : go.opentelemetry.io/otel/trace 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/trace@v1.46.0 
│                        │      │                  ╰ UID : 14c1bbc524165e75 
│                        │      ├ InstalledVersion: v1.46.0 
│                        │      ├ FixedVersion    : 1.47.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ SeveritySource  : ghsa 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │      ├ DataSource       ╭ ID  : ghsa 
│                        │      │                  ├ Name: GitHub Security Advisory Go 
│                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+
│                        │      │                          ecosystem%3Ago 
│                        │      ├ Fingerprint     : sha256:ba4fe769d7a6f15a7f11ad26aa719f3d44a196a6dda6254c6b96
│                        │      │                   76c53c640aad 
│                        │      ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │      │                   go.opentelemetry.io/otel/sdk/log:
│                        │      │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │      │                    Service via attribute truncation bypass using Unicode
│                        │      │                   replacement characters 
│                        │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │      │                    From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │      │                   version 1.35.0 until version 1.47.0, the
│                        │      │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │      │                    truncation paths in sdk/internal/attrnorm,
│                        │      │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │      │                   valid U+FFFD replacement characters. This is a distinct
│                        │      │                   incomplete-fix defect in the replacement truncation code
│                        │      │                   introduced by the remediation for CVE-2026-81869. Values
│                        │      │                   composed of or dominated by those characters can therefore
│                        │      │                   exceed the configured character and memory bound in span,
│                        │      │                   log-record, and auto-instrumentation trace attributes.
│                        │      │                   Attacker-controlled telemetry attributes can increase
│                        │      │                   retained memory and pipeline pressure, while
│                        │      │                   confidentiality and integrity are not affected. This issue
│                        │      │                   is fixed in version 1.47.0. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-135
│                        │      │                  CWE-770
│                        │      ├ VendorSeverity   ╭ ghsa  : 2 
│                        │      │                  ╰ redhat: 2 
│                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                        │      │                  │        │           N/A:L 
│                        │      │                  │        ╰ V3Score : 5.3 
│                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                        │      │                           │           N/A:L 
│                        │      │                           ╰ V3Score : 5.3 
│                        │      ├ References                                                                   
│                        │      │                  ────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-128085      
│                        │      │                  https://advisory.echohq.com/cve/CVE-2026-128085             
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go          
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/commit/01
│                        │      │                  7b08c7f1018b619991aaf6b2299d4beb9da1d3                      
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/releases/
│                        │      │                  tag/sdk/log/v1.47.0                                         
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/releases/
│                        │      │                  tag/sdk/v1.47.0                                             
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/releases/
│                        │      │                  tag/trace/v1.47.0                                           
│                        │      │                  https://github.com/open-telemetry/opentelemetry-go/security/
│                        │      │                  advisories/GHSA-q7gw-24fr-5p69                              
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085            
│                        │      │                                                                              
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-128085            
│                        │      ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │      ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [2]  ╭ VulnerabilityID : CVE-2026-78661 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6860
│                        │      ├ PkgID           : golang.org/x/net@v0.58.0 
│                        │      ├ PkgName         : golang.org/x/net 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.58.0 
│                        │      │                  ╰ UID : 7d548eeca6b3e0a1 
│                        │      ├ InstalledVersion: v0.58.0 
│                        │      ├ FixedVersion    : 0.62.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:fed2d9fe529f413176fc3b656da709d80d47608e9cdb0a8855a7
│                        │      │                   eb34eaa84459 
│                        │      ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │      │                   Service via crafted HTML input 
│                        │      ├ Description     : When coalescing adjacent text nodes in addText and
│                        │      │                   fosterParent, appending to an existing TextNode's Data via
│                        │      │                   string concatenation (n.Data += text) reallocated and
│                        │      │                   copied the accumulated string on every token. Inputs
│                        │      │                   containing many short text runs separated by ignored end
│                        │      │                   tags (such as "a</x>") caused O(n^2) allocations and byte
│                        │      │                   copies. Accumulate coalesced text in per-node byte slices
│                        │      │                   during parsing and materialize Data strings once at the end
│                        │      │                    of parse. 
│                        │      ├ Severity        : HIGH 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-407
│                        │      ├ VendorSeverity   ╭ amazon: 3 
│                        │      │                  ├ azure : 2 
│                        │      │                  ╰ redhat: 3 
│                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                        │      │                           │           N/A:H 
│                        │      │                           ╰ V3Score : 7.5 
│                        │      ├ References                                                                
│                        │      │                  ─────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │      │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │      │                  https://go.dev/cl/849365                                 
│                        │      │                  https://go.dev/issue/82224                               
│                        │      │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │      ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │      ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [3]  ╭ VulnerabilityID : CVE-2026-78669 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6611
│                        │      ├ PkgID           : golang.org/x/net@v0.58.0 
│                        │      ├ PkgName         : golang.org/x/net 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.58.0 
│                        │      │                  ╰ UID : 7d548eeca6b3e0a1 
│                        │      ├ InstalledVersion: v0.58.0 
│                        │      ├ FixedVersion    : 0.60.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78669 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:fd80165889f230e04732fc44c09a55bea198e68992665de29f61
│                        │      │                   f0b4f8dad012 
│                        │      ├ Title           : net/http: net/http/internal/http2: golang.org/x/net/http2:
│                        │      │                   net/http: Denial of Service via excessive HTTP/2 SETTINGS
│                        │      │                   frames 
│                        │      ├ Description     : A malicious HTTP/2 peer can cause excessive CPU consumption
│                        │      │                    in the client or server by opening a large number of
│                        │      │                   streams and then sending many small SETTINGS frames
│                        │      │                   containing SETTINGS_INITIAL_WINDOW_SIZE values. 
│                        │      ├ Severity        : HIGH 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-405
│                        │      ├ VendorSeverity   ╭ alma       : 3 
│                        │      │                  ├ amazon     : 3 
│                        │      │                  ├ azure      : 3 
│                        │      │                  ├ bitnami    : 3 
│                        │      │                  ├ oracle-oval: 3 
│                        │      │                  ├ redhat     : 3 
│                        │      │                  ├ rocky      : 3 
│                        │      │                  ╰ ubuntu     : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98479              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98617              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78669         
│                        │      │                  https://bugzilla.redhat.com/2484207                           
│                        │      │                  https://bugzilla.redhat.com/2515815                           
│                        │      │                  https://bugzilla.redhat.com/2515820                           
│                        │      │                  https://bugzilla.redhat.com/2515839                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515815           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515820           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515827           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515838           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515839           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-33818 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56853 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56858 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56860 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56862 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-98617.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:98479                 
│                        │      │                  https://github.com/golang/go/issues/81742                     
│                        │      │                  https://go.dev/cl/847186                                      
│                        │      │                  https://go.dev/cl/847308                                      
│                        │      │                  https://go.dev/issue/81742                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://groups.google.com/g/golang-announce/c/ZPwCyRUuGBs     
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-78669.html              
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-98617.html          
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78669               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6611                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78669               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:04.01Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:49.857Z 
│                        ├ [4]  ╭ VulnerabilityID : CVE-2026-78659 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6603
│                        │      ├ PkgID           : golang.org/x/net@v0.58.0 
│                        │      ├ PkgName         : golang.org/x/net 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.58.0 
│                        │      │                  ╰ UID : 7d548eeca6b3e0a1 
│                        │      ├ InstalledVersion: v0.58.0 
│                        │      ├ FixedVersion    : 0.60.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78659 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:08df0b076fe62677d9d3a2aee52c4a890fb356ef5bc64c639f93
│                        │      │                   49d2e51439f7 
│                        │      ├ Title           : net/http: golang.org/x/net/http2: golang: net/http: Denial
│                        │      │                   of Service via HTTP/2 trailer header memory exhaustion 
│                        │      ├ Description     : When "Trailer" headers are sent by a client, the HTTP
│                        │      │                   server internally uses the header values to populate the
│                        │      │                   Request.Trailer map passed to the server handler. Because
│                        │      │                   Request.Trailer is a map, each entry incurs memory
│                        │      │                   overhead. For HTTP/2 servers, a malicious client can
│                        │      │                   exploit this by sending a "Trailer" header that declares a
│                        │      │                   large number of fields, causing the server to allocate a
│                        │      │                   disproportionate amount of memory while bypassing
│                        │      │                   Server.MaxHeaderValueCount and Server.MaxHeaderBytes
│                        │      │                   limits. This exploit is not applicable for HTTP/1 servers,
│                        │      │                   which do not support multiplexing a large number of
│                        │      │                   requests over one TCP connection, and whose
│                        │      │                   Server.MaxHeaderBytes are calculated differently. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-405
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 3 
│                        │      │                  ├ azure  : 3 
│                        │      │                  ├ bitnami: 3 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ├ rocky  : 3 
│                        │      │                  ╰ ubuntu : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78659         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81857                     
│                        │      │                  https://go.dev/cl/847185                                      
│                        │      │                  https://go.dev/cl/847314                                      
│                        │      │                  https://go.dev/issue/81857                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://groups.google.com/g/golang-announce/c/ZPwCyRUuGBs     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78659               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6603                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78659               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:03.27Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T16:35:35.9Z 
│                        ├ [5]  ╭ VulnerabilityID : CVE-2026-78660 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6610
│                        │      ├ PkgID           : golang.org/x/net@v0.58.0 
│                        │      ├ PkgName         : golang.org/x/net 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.58.0 
│                        │      │                  ╰ UID : 7d548eeca6b3e0a1 
│                        │      ├ InstalledVersion: v0.58.0 
│                        │      ├ FixedVersion    : 0.60.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78660 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:bebd2c9d774a7d00852359aa3add51e11b67f4a6b27bae712c2c
│                        │      │                   143054b92d75 
│                        │      ├ Title           : net/http: golang: golang.org/x/net/http2: net/http: HTTP
│                        │      │                   response smuggling via malformed HTTP/2 framing headers 
│                        │      ├ Description     : Historically, we have been rather lax about malformed
│                        │      │                   framing-related headers in our HTTP/2 implementation, as
│                        │      │                   they cannot interfere with HTTP/2 framing. However, this
│                        │      │                   makes it possible for our HTTP/2 implementation to forward
│                        │      │                   responses containing such headers to an HTTP/1 client when
│                        │      │                   acting as a reverse proxy. If the HTTP/1 client also does
│                        │      │                   not behave strictly enough, this can result in response
│                        │      │                   smuggling. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-444
│                        │      ├ VendorSeverity   ╭ alma       : 2 
│                        │      │                  ├ amazon     : 3 
│                        │      │                  ├ azure      : 3 
│                        │      │                  ├ bitnami    : 3 
│                        │      │                  ├ oracle-oval: 2 
│                        │      │                  ├ photon     : 3 
│                        │      │                  ├ redhat     : 2 
│                        │      │                  ├ rocky      : 3 
│                        │      │                  ╰ ubuntu     : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :H/A:N 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :H/A:N 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:93464              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78660         
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-93464.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81115                     
│                        │      │                  https://go.dev/cl/835145                                      
│                        │      │                  https://go.dev/cl/836385                                      
│                        │      │                  https://go.dev/issue/81115                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-78660.html              
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-103499.html         
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78660               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6610                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78660               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:03.51Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:49.243Z 
│                        ├ [6]  ╭ VulnerabilityID : CVE-2026-78663 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6612
│                        │      ├ PkgID           : golang.org/x/net@v0.58.0 
│                        │      ├ PkgName         : golang.org/x/net 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.58.0 
│                        │      │                  ╰ UID : 7d548eeca6b3e0a1 
│                        │      ├ InstalledVersion: v0.58.0 
│                        │      ├ FixedVersion    : 0.60.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78663 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:60d11e44a6af150b722642171a0f7cce491d3652c05f28c25234
│                        │      │                   53238a95ae9c 
│                        │      ├ Title           : net/http: net/http/internal/http2: golang:
│                        │      │                   golang.org/x/net/http2: golang: flow control limit bypass
│                        │      │                   via double refund in HTTP/2 server 
│                        │      ├ Description     : The HTTP/2 server can refund connection-level flow control
│                        │      │                   twice for the same data: Once when a client resets a stream
│                        │      │                    (refunding data for any sent-but-unread portion of the
│                        │      │                   stream), and again when a request handler reads the
│                        │      │                   buffered data. A malicious client can exploit this to
│                        │      │                   bypass the configured connection-level flow control limit
│                        │      │                   (MaxReceiveBufferPerConnection). Total buffered data is
│                        │      │                   still limited by the concurrent stream limit and
│                        │      │                   stream-level flow control. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-675
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 2 
│                        │      │                  ├ azure  : 3 
│                        │      │                  ├ bitnami: 4 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ├ rocky  : 3 
│                        │      │                  ╰ ubuntu : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :H/A:H 
│                        │      │                  │         ╰ V3Score : 9.1 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:L 
│                        │      │                            ╰ V3Score : 5.3 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78663         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81743                     
│                        │      │                  https://go.dev/cl/847187                                      
│                        │      │                  https://go.dev/cl/847310                                      
│                        │      │                  https://go.dev/issue/81743                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://groups.google.com/g/golang-announce/c/ZPwCyRUuGBs     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78663               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6612                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78663               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:03.647Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:49.42Z 
│                        ├ [7]  ╭ VulnerabilityID : CVE-2026-97032 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6617
│                        │      ├ PkgID           : golang.org/x/net@v0.58.0 
│                        │      ├ PkgName         : golang.org/x/net 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.58.0 
│                        │      │                  ╰ UID : 7d548eeca6b3e0a1 
│                        │      ├ InstalledVersion: v0.58.0 
│                        │      ├ FixedVersion    : 0.60.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97032 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:7fd87de3352a6cf9ed2e23c3a0fa1a10e009e331496f17d2b17a
│                        │      │                   bd91619d20d0 
│                        │      ├ Title           : net/http: net/http/internal/http2: golang:
│                        │      │                   golang.org/x/net/http2: net/http: Denial of Service via
│                        │      │                   concurrent HPACK encoder modification 
│                        │      ├ Description     : HTTP/2 servers could end up crashing due to inadvertently
│                        │      │                   modifying its HPACK encoder concurrently. This happens
│                        │      │                   because the server modifies the HPACK encoder from two
│                        │      │                   goroutines without synchronization: one uses the encoder to
│                        │      │                    encode a HEADERS frame as part of a response sent to a
│                        │      │                   client and the other modifies the encoder's table size when
│                        │      │                    handling a SETTINGS frame containing
│                        │      │                   SETTINGS_HEADER_TABLE_SIZE that a client sends. A malicious
│                        │      │                    client can repeatedly send a request while changing the
│                        │      │                   header table size to crash the server. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-362
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 3 
│                        │      │                  ├ azure  : 3 
│                        │      │                  ├ bitnami: 3 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ├ rocky  : 3 
│                        │      │                  ╰ ubuntu : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 5.9 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-97032         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81867                     
│                        │      │                  https://go.dev/cl/847188                                      
│                        │      │                  https://go.dev/cl/847313                                      
│                        │      │                  https://go.dev/issue/81867                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://groups.google.com/g/golang-announce/c/ZPwCyRUuGBs     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97032               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6617                          
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-97032               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:06.213Z 
│                        │      ╰ LastModifiedDate: 2026-10-15T16:18:24.967Z 
│                        ├ [8]  ╭ VulnerabilityID : CVE-2026-97045 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6866
│                        │      ├ PkgID           : golang.org/x/net@v0.58.0 
│                        │      ├ PkgName         : golang.org/x/net 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.58.0 
│                        │      │                  ╰ UID : 7d548eeca6b3e0a1 
│                        │      ├ InstalledVersion: v0.58.0 
│                        │      ├ FixedVersion    : 0.62.0 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:7e4faf1765fb04a49d9df17704803459b310fed88560d0f0217e
│                        │      │                   f763e219b763 
│                        │      ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │      │                   Scripting via improper namespace handling during HTML
│                        │      │                   rendering 
│                        │      ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │      │                    stopped at the nearest foreign ancestor once an HTML
│                        │      │                   integration point was found. However, that integration
│                        │      │                   point may itself be a descendant of an element that was
│                        │      │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │      │                   or <malignmark> fostered under <mtext>), causing a parser
│                        │      │                   to resolve the subtree in a different foreign namespace
│                        │      │                   upon re-parsing the rendered output. Continue walking the
│                        │      │                   full ancestor chain and verify that every transition from a
│                        │      │                    non-empty namespace occurs at an HTML integration point
│                        │      │                   before emitting literal text. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                 
│                        │      │                  ──────
│                        │      │                  CWE-79
│                        │      ├ VendorSeverity   ╭ amazon: 3 
│                        │      │                  ├ azure : 2 
│                        │      │                  ╰ redhat: 2 
│                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                        │      │                           │           L/A:N 
│                        │      │                           ╰ V3Score : 6.1 
│                        │      ├ References                                                                
│                        │      │                  ─────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │      │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │      │                  https://go.dev/cl/855121                                 
│                        │      │                  https://go.dev/issue/82622                               
│                        │      │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │      ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │      ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ├ [9]  ╭ VulnerabilityID : CVE-2026-111943 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6809
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.10, 1.27.3 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-111943 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:51c48d8c6f904842da80f3261f3cd97c6a41f2091cc6221e7f2d
│                        │      │                   ba34767fd296 
│                        │      ├ Title           : crypto/x509: golang: crypto/x509: Man-in-the-middle attacks
│                        │      │                    via untrusted intermediate certificates 
│                        │      ├ Description     : On most platforms, Go uses the given system root
│                        │      │                   certificates. However, in some narrower cases, the system
│                        │      │                   trust stores may not be updated without further action. To
│                        │      │                   defend against the narrower set of cases that may remain
│                        │      │                   affected, a denylist was added in crypto/x509 to return an
│                        │      │                   error when calling Verify with any of the known
│                        │      │                   intermediate certificates that are no longer considered to
│                        │      │                   be trustworthy. 
│                        │      ├ Severity        : HIGH 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-299
│                        │      ├ VendorSeverity   ╭ alma       : 3 
│                        │      │                  ├ amazon     : 3 
│                        │      │                  ├ bitnami    : 2 
│                        │      │                  ├ oracle-oval: 3 
│                        │      │                  ├ photon     : 2 
│                        │      │                  ├ redhat     : 3 
│                        │      │                  ╰ rocky      : 3 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I
│                        │      │                  │         │           :H/A:N 
│                        │      │                  │         ╰ V3Score : 6.8 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I
│                        │      │                            │           :H/A:N 
│                        │      │                            ╰ V3Score : 6.8 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  http://www.openwall.com/lists/oss-security/2026/10/20/29      
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98539              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98610              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-111943        
│                        │      │                  https://bugzilla.redhat.com/2515815                           
│                        │      │                  https://bugzilla.redhat.com/2515827                           
│                        │      │                  https://bugzilla.redhat.com/2515839                           
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548341                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-98610.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:98539                 
│                        │      │                  https://github.com/golang/go/issues/82345                     
│                        │      │                  https://go.dev/cl/851047                                      
│                        │      │                  https://go.dev/issue/82345                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/66pojueaQek     
│                        │      │                  https://groups.google.com/g/golang-nuts/c/K22sG2AYnKU         
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-111943.html             
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-98610.html          
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-111943              
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6809                          
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-111943              
│                        │      ├ PublishedDate   : 2026-10-21T01:17:20.797Z 
│                        │      ╰ LastModifiedDate: 2026-10-30T13:18:28.74Z 
│                        ├ [10] ╭ VulnerabilityID : CVE-2026-78667 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6609
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78667 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:fac03f20aae031774acb46253d9dbf9c3e014217a1bb7a34ede5
│                        │      │                   7beafcd70ed4 
│                        │      ├ Title           : net/http: golang: golang: Denial of Service via crafted
│                        │      │                   HTTP Range headers 
│                        │      ├ Description     : When parsing a Range header containing a large number of
│                        │      │                   small ranges, FileServer(FS), ServeContent, and
│                        │      │                   ServeFile(FS) can consume an excessive amount of CPU. 
│                        │      ├ Severity        : HIGH 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-770
│                        │      ├ VendorSeverity   ╭ alma       : 3 
│                        │      │                  ├ amazon     : 3 
│                        │      │                  ├ bitnami    : 3 
│                        │      │                  ├ oracle-oval: 3 
│                        │      │                  ├ redhat     : 3 
│                        │      │                  ├ rocky      : 3 
│                        │      │                  ╰ ubuntu     : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98502              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98610              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78667         
│                        │      │                  https://bugzilla.redhat.com/2515815                           
│                        │      │                  https://bugzilla.redhat.com/2515827                           
│                        │      │                  https://bugzilla.redhat.com/2515839                           
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548341                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515815           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515827           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515839           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-33818 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56853 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56862 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-98610.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:98502                 
│                        │      │                  https://github.com/golang/go/issues/81858                     
│                        │      │                  https://go.dev/cl/847309                                      
│                        │      │                  https://go.dev/issue/81858                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-78667.html              
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-98610.html          
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78667               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6609                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78667               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:03.88Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:49.69Z 
│                        ├ [11] ╭ VulnerabilityID : CVE-2026-78669 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6611
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78669 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:897338ebfecf1c85ecffc287c01f14a92202a3544418f27c39f9
│                        │      │                   bffeebfab36e 
│                        │      ├ Title           : net/http: net/http/internal/http2: golang.org/x/net/http2:
│                        │      │                   net/http: Denial of Service via excessive HTTP/2 SETTINGS
│                        │      │                   frames 
│                        │      ├ Description     : A malicious HTTP/2 peer can cause excessive CPU consumption
│                        │      │                    in the client or server by opening a large number of
│                        │      │                   streams and then sending many small SETTINGS frames
│                        │      │                   containing SETTINGS_INITIAL_WINDOW_SIZE values. 
│                        │      ├ Severity        : HIGH 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-405
│                        │      ├ VendorSeverity   ╭ alma       : 3 
│                        │      │                  ├ amazon     : 3 
│                        │      │                  ├ azure      : 3 
│                        │      │                  ├ bitnami    : 3 
│                        │      │                  ├ oracle-oval: 3 
│                        │      │                  ├ redhat     : 3 
│                        │      │                  ├ rocky      : 3 
│                        │      │                  ╰ ubuntu     : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98479              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98617              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78669         
│                        │      │                  https://bugzilla.redhat.com/2484207                           
│                        │      │                  https://bugzilla.redhat.com/2515815                           
│                        │      │                  https://bugzilla.redhat.com/2515820                           
│                        │      │                  https://bugzilla.redhat.com/2515839                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515815           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515820           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515827           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515838           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515839           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-33818 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56853 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56858 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56860 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56862 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-98617.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:98479                 
│                        │      │                  https://github.com/golang/go/issues/81742                     
│                        │      │                  https://go.dev/cl/847186                                      
│                        │      │                  https://go.dev/cl/847308                                      
│                        │      │                  https://go.dev/issue/81742                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://groups.google.com/g/golang-announce/c/ZPwCyRUuGBs     
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-78669.html              
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-98617.html          
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78669               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6611                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78669               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:04.01Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:49.857Z 
│                        ├ [12] ╭ VulnerabilityID : CVE-2026-97031 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6607
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97031 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:825a662ea3dffdd23fa12f6268cfa0a98ca96c278d747ffa9aa6
│                        │      │                   1e7e790f5590 
│                        │      ├ Title           : crypto/tls: golang: crypto/tls: Denial of Service via
│                        │      │                   multiple ECH outer extension references 
│                        │      ├ Description     : Multiple ECH outer extension references are not permitted
│                        │      │                   under RFC 9849; previously, a client could send a
│                        │      │                   well-crafted packet that could trigger memory exhaustion in
│                        │      │                    the server process by specifying multiple references. We
│                        │      │                   now reject these as malformed and curb the memory
│                        │      │                   amplification vector as a result. 
│                        │      ├ Severity        : HIGH 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-405
│                        │      ├ VendorSeverity   ╭ alma       : 3 
│                        │      │                  ├ amazon     : 3 
│                        │      │                  ├ bitnami    : 3 
│                        │      │                  ├ oracle-oval: 3 
│                        │      │                  ├ redhat     : 3 
│                        │      │                  ╰ rocky      : 3 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98502              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98610              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-97031         
│                        │      │                  https://bugzilla.redhat.com/2515815                           
│                        │      │                  https://bugzilla.redhat.com/2515827                           
│                        │      │                  https://bugzilla.redhat.com/2515839                           
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548341                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515815           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515827           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515839           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-33818 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56853 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56862 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-98610.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:98502                 
│                        │      │                  https://go.dev/cl/847312                                      
│                        │      │                  https://go.dev/issue/81855                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-97031.html              
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-98610.html          
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97031               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6607                          
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-97031               
│                        │      ├ PublishedDate   : 2026-10-08T23:17:06.037Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T16:35:35.9Z 
│                        ├ [13] ╭ VulnerabilityID : CVE-2026-56866 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6605
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56866 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:33eed1d0a5a7cca315b12119c4be6dd469e509a9244a60dd117e
│                        │      │                   627ed6e5163c 
│                        │      ├ Title           : net/http: golang: golang: Cross-user response poisoning via
│                        │      │                    desynchronized HTTP CONNECT connections 
│                        │      ├ Description     : When http.Transport sends an HTTP/1 CONNECT request with a
│                        │      │                   non-empty Request.Body, it writes the body directly to the
│                        │      │                   connection without framing after the request headers. If
│                        │      │                   the server rejects the CONNECT request with a non-2xx
│                        │      │                   keep-alive response, Transport returns the connection to
│                        │      │                   the idle pool. Because CONNECT requests do not have a
│                        │      │                   request body, the server may interpret the trailing body
│                        │      │                   bytes as a subsequent pipelined HTTP/1.1 request on the
│                        │      │                   connection, leaving the pooled connection desynchronized
│                        │      │                   and causing the next caller that reuses it to read the
│                        │      │                   response to the injected request. In reverse proxies
│                        │      │                   (including httputil.ReverseProxy) that forward CONNECT
│                        │      │                   requests through a shared Transport, this can lead to
│                        │      │                   cross-user response poisoning. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-444
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 3 
│                        │      │                  ├ bitnami: 3 
│                        │      │                  ├ photon : 3 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ├ rocky  : 3 
│                        │      │                  ╰ ubuntu : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I
│                        │      │                  │         │           :N/A:N 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I
│                        │      │                            │           :L/A:N 
│                        │      │                            ╰ V3Score : 6.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-56866         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81740                     
│                        │      │                  https://go.dev/cl/847306                                      
│                        │      │                  https://go.dev/issue/81740                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-56866               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6605                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-56866               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:01.62Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T16:35:35.9Z 
│                        ├ [14] ╭ VulnerabilityID : CVE-2026-78659 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6603
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78659 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:f41247e2b3a08e1b7baff08fc6d1dee6087d68b3f556e9a0fb58
│                        │      │                   e3800581f40e 
│                        │      ├ Title           : net/http: golang.org/x/net/http2: golang: net/http: Denial
│                        │      │                   of Service via HTTP/2 trailer header memory exhaustion 
│                        │      ├ Description     : When "Trailer" headers are sent by a client, the HTTP
│                        │      │                   server internally uses the header values to populate the
│                        │      │                   Request.Trailer map passed to the server handler. Because
│                        │      │                   Request.Trailer is a map, each entry incurs memory
│                        │      │                   overhead. For HTTP/2 servers, a malicious client can
│                        │      │                   exploit this by sending a "Trailer" header that declares a
│                        │      │                   large number of fields, causing the server to allocate a
│                        │      │                   disproportionate amount of memory while bypassing
│                        │      │                   Server.MaxHeaderValueCount and Server.MaxHeaderBytes
│                        │      │                   limits. This exploit is not applicable for HTTP/1 servers,
│                        │      │                   which do not support multiplexing a large number of
│                        │      │                   requests over one TCP connection, and whose
│                        │      │                   Server.MaxHeaderBytes are calculated differently. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-405
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 3 
│                        │      │                  ├ azure  : 3 
│                        │      │                  ├ bitnami: 3 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ├ rocky  : 3 
│                        │      │                  ╰ ubuntu : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78659         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81857                     
│                        │      │                  https://go.dev/cl/847185                                      
│                        │      │                  https://go.dev/cl/847314                                      
│                        │      │                  https://go.dev/issue/81857                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://groups.google.com/g/golang-announce/c/ZPwCyRUuGBs     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78659               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6603                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78659               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:03.27Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T16:35:35.9Z 
│                        ├ [15] ╭ VulnerabilityID : CVE-2026-78660 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6610
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78660 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:855aba8f302ff670aa5c8d441c19644ba1932150ac7257814c8a
│                        │      │                   1029e9b49657 
│                        │      ├ Title           : net/http: golang: golang.org/x/net/http2: net/http: HTTP
│                        │      │                   response smuggling via malformed HTTP/2 framing headers 
│                        │      ├ Description     : Historically, we have been rather lax about malformed
│                        │      │                   framing-related headers in our HTTP/2 implementation, as
│                        │      │                   they cannot interfere with HTTP/2 framing. However, this
│                        │      │                   makes it possible for our HTTP/2 implementation to forward
│                        │      │                   responses containing such headers to an HTTP/1 client when
│                        │      │                   acting as a reverse proxy. If the HTTP/1 client also does
│                        │      │                   not behave strictly enough, this can result in response
│                        │      │                   smuggling. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-444
│                        │      ├ VendorSeverity   ╭ alma       : 2 
│                        │      │                  ├ amazon     : 3 
│                        │      │                  ├ azure      : 3 
│                        │      │                  ├ bitnami    : 3 
│                        │      │                  ├ oracle-oval: 2 
│                        │      │                  ├ photon     : 3 
│                        │      │                  ├ redhat     : 2 
│                        │      │                  ├ rocky      : 3 
│                        │      │                  ╰ ubuntu     : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :H/A:N 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :H/A:N 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:93464              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78660         
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-93464.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81115                     
│                        │      │                  https://go.dev/cl/835145                                      
│                        │      │                  https://go.dev/cl/836385                                      
│                        │      │                  https://go.dev/issue/81115                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-78660.html              
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-103499.html         
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78660               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6610                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78660               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:03.51Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:49.243Z 
│                        ├ [16] ╭ VulnerabilityID : CVE-2026-78663 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6612
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78663 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:5159b5ea8f17abd84d1ecaa008cedfbaa318c6637db082bf2c9b
│                        │      │                   502df5cf3556 
│                        │      ├ Title           : net/http: net/http/internal/http2: golang:
│                        │      │                   golang.org/x/net/http2: golang: flow control limit bypass
│                        │      │                   via double refund in HTTP/2 server 
│                        │      ├ Description     : The HTTP/2 server can refund connection-level flow control
│                        │      │                   twice for the same data: Once when a client resets a stream
│                        │      │                    (refunding data for any sent-but-unread portion of the
│                        │      │                   stream), and again when a request handler reads the
│                        │      │                   buffered data. A malicious client can exploit this to
│                        │      │                   bypass the configured connection-level flow control limit
│                        │      │                   (MaxReceiveBufferPerConnection). Total buffered data is
│                        │      │                   still limited by the concurrent stream limit and
│                        │      │                   stream-level flow control. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-675
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 2 
│                        │      │                  ├ azure  : 3 
│                        │      │                  ├ bitnami: 4 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ├ rocky  : 3 
│                        │      │                  ╰ ubuntu : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :H/A:H 
│                        │      │                  │         ╰ V3Score : 9.1 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:L 
│                        │      │                            ╰ V3Score : 5.3 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-78663         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81743                     
│                        │      │                  https://go.dev/cl/847187                                      
│                        │      │                  https://go.dev/cl/847310                                      
│                        │      │                  https://go.dev/issue/81743                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://groups.google.com/g/golang-announce/c/ZPwCyRUuGBs     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78663               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6612                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-78663               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:03.647Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:49.42Z 
│                        ├ [17] ╭ VulnerabilityID : CVE-2026-94439 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6613
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-94439 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:bfe8eac7a761be35372a6541363e8bec2254aa03addd378ae461
│                        │      │                   c6480db3ce4e 
│                        │      ├ Title           : net/http: golang: net/http: HTTP request smuggling via
│                        │      │                   improper handling of HTTP/1 CONNECT responses 
│                        │      ├ Description     : When an HTTP server handler sends a 2xx response to an
│                        │      │                   HTTP/1 CONNECT request and returns without hijacking the
│                        │      │                   connection, the server improperly continues to read and
│                        │      │                   serve requests from the connection. Since a 2xx response to
│                        │      │                    an HTTP/1 CONNECT converts the connection into a tunnel,
│                        │      │                   the server should not treat the connection as continuing to
│                        │      │                    contain HTTP. The impact of this misbehavior is mostly
│                        │      │                   limited to potential request smuggling, where an
│                        │      │                   intermediate proxy considers the data on the connection to
│                        │      │                   be tunneled and the server considers it to be HTTP. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-444
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 2 
│                        │      │                  ├ bitnami: 3 
│                        │      │                  ├ photon : 3 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ├ rocky  : 3 
│                        │      │                  ╰ ubuntu : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I
│                        │      │                  │         │           :N/A:N 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I
│                        │      │                            │           :L/A:N 
│                        │      │                            ╰ V3Score : 6.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-94439         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81744                     
│                        │      │                  https://go.dev/cl/847311                                      
│                        │      │                  https://go.dev/issue/81744                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-94439               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6613                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-94439               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:04.76Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:50.703Z 
│                        ├ [18] ╭ VulnerabilityID : CVE-2026-94440 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6608
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-94440 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:8a8a470e40051612ec3d08c7cabdc5d50083cd952007790b0bb9
│                        │      │                   a315f0b0c3c4 
│                        │      ├ Title           : net/textproto: mime/multipart: golang: golang: Denial of
│                        │      │                   Service via memory limit bypass in multipart form parsing[
│                        │      │                   m 
│                        │      ├ Description     : Parsing a multipart form can bypass memory limits and read
│                        │      │                   an arbitrarily long line into memory when the remaining
│                        │      │                   limit at the start of a part is less than 400 bytes. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-770
│                        │      ├ VendorSeverity   ╭ alma       : 3 
│                        │      │                  ├ amazon     : 3 
│                        │      │                  ├ bitnami    : 3 
│                        │      │                  ├ oracle-oval: 3 
│                        │      │                  ├ redhat     : 2 
│                        │      │                  ├ rocky      : 3 
│                        │      │                  ╰ ubuntu     : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 7.5 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98502              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:98610              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-94440         
│                        │      │                  https://bugzilla.redhat.com/2515815                           
│                        │      │                  https://bugzilla.redhat.com/2515827                           
│                        │      │                  https://bugzilla.redhat.com/2515839                           
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548341                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515815           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515827           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2515839           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-33818 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56853 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56862 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-98610.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:98502                 
│                        │      │                  https://github.com/golang/go/issues/81741                     
│                        │      │                  https://go.dev/cl/847307                                      
│                        │      │                  https://go.dev/issue/81741                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-94440.html              
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-98610.html          
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-94440               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6608                          
│                        │      │                  https://ubuntu.com/security/notices/USN-8935-1                
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-94440               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:04.917Z 
│                        │      ╰ LastModifiedDate: 2026-10-09T17:16:50.907Z 
│                        ├ [19] ╭ VulnerabilityID : CVE-2026-94448 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6599
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-94448 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:35e6ae0c519baca845097991e0acf6fbdb3b84157b60b627b01f
│                        │      │                   b32691a74d02 
│                        │      ├ Title           : html/template: golang: golang: cross-site scripting via
│                        │      │                   consecutive expressions in JavaScript template literals 
│                        │      ├ Description     : When a JavaScript template literal contains consecutive
│                        │      │                   expressions, the context tracking state was not properly
│                        │      │                   reset upon entering a new expression. We now ensure that
│                        │      │                   template-literal expression entries correctly reset context
│                        │      │                    variables so all subsequent regular expression literals
│                        │      │                   are accurately recognized and escaped. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                 
│                        │      │                  ──────
│                        │      │                  CWE-79
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 2 
│                        │      │                  ├ bitnami: 2 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ╰ rocky  : 3 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I
│                        │      │                  │         │           :L/A:N 
│                        │      │                  │         ╰ V3Score : 6.1 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I
│                        │      │                            │           :L/A:N 
│                        │      │                            ╰ V3Score : 6.1 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-94448         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://go.dev/cl/839866                                      
│                        │      │                  https://go.dev/issue/81821                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-94448               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6599                          
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-94448               
│                        │      ├ PublishedDate   : 2026-10-08T23:17:05.3Z 
│                        │      ╰ LastModifiedDate: 2026-10-15T16:18:24.327Z 
│                        ├ [20] ╭ VulnerabilityID : CVE-2026-97030 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6600
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97030 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:29f2427f004118f428b18dd1c2bfd8c9fbb60f280268ae088544
│                        │      │                   9a819caabacc 
│                        │      ├ Title           : html/template: golang: html/template: Cross-site scripting
│                        │      │                   via improper escaping of yield keyword 
│                        │      ├ Description     : A trusted template author may have previously written a
│                        │      │                   valid template wherein the use of the 'yield' keyword would
│                        │      │                    not be correctly escaped. We now ensure that valid keyword
│                        │      │                    uses are escaped and non-keyword uses are not escaped. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                 
│                        │      │                  ──────
│                        │      │                  CWE-79
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 2 
│                        │      │                  ├ bitnami: 2 
│                        │      │                  ├ photon : 2 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ╰ rocky  : 3 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I
│                        │      │                  │         │           :L/A:N 
│                        │      │                  │         ╰ V3Score : 6.1 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I
│                        │      │                            │           :L/A:N 
│                        │      │                            ╰ V3Score : 6.1 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-97030         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://go.dev/cl/840925                                      
│                        │      │                  https://go.dev/issue/81823                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97030               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6600                          
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-97030               
│                        │      ├ PublishedDate   : 2026-10-08T23:17:05.91Z 
│                        │      ╰ LastModifiedDate: 2026-10-15T16:18:24.817Z 
│                        ├ [21] ╭ VulnerabilityID : CVE-2026-97032 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6617
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.9, 1.27.2 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97032 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:5e046c21164111d82aaed16ac1258311d20111ba82f9ab01ec43
│                        │      │                   f116f66fd922 
│                        │      ├ Title           : net/http: net/http/internal/http2: golang:
│                        │      │                   golang.org/x/net/http2: net/http: Denial of Service via
│                        │      │                   concurrent HPACK encoder modification 
│                        │      ├ Description     : HTTP/2 servers could end up crashing due to inadvertently
│                        │      │                   modifying its HPACK encoder concurrently. This happens
│                        │      │                   because the server modifies the HPACK encoder from two
│                        │      │                   goroutines without synchronization: one uses the encoder to
│                        │      │                    encode a HEADERS frame as part of a response sent to a
│                        │      │                   client and the other modifies the encoder's table size when
│                        │      │                    handling a SETTINGS frame containing
│                        │      │                   SETTINGS_HEADER_TABLE_SIZE that a client sends. A malicious
│                        │      │                    client can repeatedly send a request while changing the
│                        │      │                   header table size to crash the server. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-362
│                        │      ├ VendorSeverity   ╭ alma   : 3 
│                        │      │                  ├ amazon : 3 
│                        │      │                  ├ azure  : 3 
│                        │      │                  ├ bitnami: 3 
│                        │      │                  ├ redhat : 2 
│                        │      │                  ├ rocky  : 3 
│                        │      │                  ╰ ubuntu : 2 
│                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I
│                        │      │                  │         │           :N/A:H 
│                        │      │                  │         ╰ V3Score : 7.5 
│                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I
│                        │      │                            │           :N/A:H 
│                        │      │                            ╰ V3Score : 5.9 
│                        │      ├ References                                                                     
│                        │      │                  ──────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86093              
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:86196              
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-97032         
│                        │      │                  https://bugzilla.redhat.com/2548334                           
│                        │      │                  https://bugzilla.redhat.com/2548336                           
│                        │      │                  https://bugzilla.redhat.com/2548344                           
│                        │      │                  https://bugzilla.redhat.com/2556068                           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548334           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548335           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548336           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548337           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548338           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548339           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548340           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548341           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548342           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548343           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548344           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548345           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548346           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2548347           
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2556068           
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                  
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-111943
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-56866 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78659 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78660 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78663 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78667 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-78669 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94439 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94440 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94444 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94447 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-94448 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97030 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97031 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97032 
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-86093.html          
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:86196                 
│                        │      │                  https://github.com/golang/go/issues/81867                     
│                        │      │                  https://go.dev/cl/847188                                      
│                        │      │                  https://go.dev/cl/847313                                      
│                        │      │                  https://go.dev/issue/81867                                    
│                        │      │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI     
│                        │      │                  https://groups.google.com/g/golang-announce/c/ZPwCyRUuGBs     
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97032               
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6617                          
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-97032               
│                        │      │                  https://www.openwall.com/lists/oss-security/2026/10/08/9      
│                        │      ├ PublishedDate   : 2026-10-08T23:17:06.213Z 
│                        │      ╰ LastModifiedDate: 2026-10-15T16:18:24.967Z 
│                        ├ [22] ╭ VulnerabilityID : CVE-2026-97054 
│                        │      ├ VendorIDs                    
│                        │      │                  ────────────
│                        │      │                  GO-2026-6859
│                        │      ├ PkgID           : stdlib@v1.26.7 
│                        │      ├ PkgName         : stdlib 
│                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                        │      │                  ╰ UID : e8c72f6b323f774f 
│                        │      ├ InstalledVersion: v1.26.7 
│                        │      ├ FixedVersion    : 1.26.11, 1.27.4 
│                        │      ├ Status          : fixed 
│                        │      ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                        │      │                  │         8a4bbba599de722a4416d 
│                        │      │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                        │      │                            320c0db24f65fbfa6dc9e 
│                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                        │      ├ DataSource       ╭ ID  : govulndb 
│                        │      │                  ├ Name: The Go Vulnerability Database 
│                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │      ├ Fingerprint     : sha256:a8a410568b3e7c77c6e6fc8f2c24d2e13488592bf33a4be43d6e
│                        │      │                   458d49f35305 
│                        │      ├ Title           : net/http: golang: net/http: Denial of Service via race
│                        │      │                   condition when handling oversized HTTP/1 requests 
│                        │      ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is
│                        │      │                   exceeded, "Connection: close" header is automatically set
│                        │      │                   without synchronization, which might race with another
│                        │      │                   header being set explicitly in the server handler. As a
│                        │      │                   result, an HTTP/1 server that utilizes MaxBytesReader or
│                        │      │                   MaxBytesHandler can crash due to runtime panic if its
│                        │      │                   handler reads the request body concurrently with writing
│                        │      │                   the response header. 
│                        │      ├ Severity        : MEDIUM 
│                        │      ├ CweIDs                  
│                        │      │                  ───────
│                        │      │                  CWE-362
│                        │      │                  CWE-820
│                        │      ├ VendorSeverity   ╭ alma       : 2 
│                        │      │                  ├ amazon     : 2 
│                        │      │                  ├ oracle-oval: 2 
│                        │      │                  ├ photon     : 2 
│                        │      │                  ├ redhat     : 2 
│                        │      │                  ╰ rocky      : 2 
│                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
│                        │      │                           │           N/A:H 
│                        │      │                           ╰ V3Score : 5.9 
│                        │      ├ References                                                                    
│                        │      │                  ─────────────────────────────────────────────────────────────
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                        │      │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                        │      │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                        │      │                  https://bugzilla.redhat.com/2571442                          
│                        │      │                  https://bugzilla.redhat.com/2571443                          
│                        │      │                  https://bugzilla.redhat.com/2571444                          
│                        │      │                  https://bugzilla.redhat.com/2571445                          
│                        │      │                  https://bugzilla.redhat.com/2571446                          
│                        │      │                  https://bugzilla.redhat.com/2571447                          
│                        │      │                  https://bugzilla.redhat.com/2571448                          
│                        │      │                  https://bugzilla.redhat.com/2571449                          
│                        │      │                  https://bugzilla.redhat.com/2571450                          
│                        │      │                  https://bugzilla.redhat.com/2571451                          
│                        │      │                  https://bugzilla.redhat.com/2571452                          
│                        │      │                  https://bugzilla.redhat.com/2571453                          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                        │      │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                        │      │                  https://creativecommons.org/licenses/by/4.0/                 
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                        │      │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                        │      │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                        │      │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                        │      │                  https://go.dev/cl/862185                                     
│                        │      │                  https://go.dev/issue/82563                                   
│                        │      │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                        │      │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                        │      │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                        │      │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                        │      │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                        │      │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                        │      ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                        │      ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
│                        ╰ [23] ╭ VulnerabilityID : CVE-2026-56857 
│                               ├ VendorIDs                    
│                               │                  ────────────
│                               │                  GO-2026-6604
│                               ├ PkgID           : stdlib@v1.26.7 
│                               ├ PkgName         : stdlib 
│                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.7 
│                               │                  ╰ UID : e8c72f6b323f774f 
│                               ├ InstalledVersion: v1.26.7 
│                               ├ FixedVersion    : 1.26.9, 1.27.2 
│                               ├ Status          : fixed 
│                               ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c
│                               │                  │         8a4bbba599de722a4416d 
│                               │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f36687
│                               │                            320c0db24f65fbfa6dc9e 
│                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56857 
│                               ├ DataSource       ╭ ID  : govulndb 
│                               │                  ├ Name: The Go Vulnerability Database 
│                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                               ├ Fingerprint     : sha256:ecf88874f8486ec9c2ea92ace0f4fa59e124ad1da2da6df6199c
│                               │                   6975b02e1c2f 
│                               ├ Title           : os: golang: golang: Directory traversal via Windows
│                               │                   junction handling 
│                               ├ Description     : On Windows, when the target of Root.Mkdir or Root.MkdirAll
│                               │                   is a junction pointing to an empty location, the operation
│                               │                   can create a directory at the junction target even when
│                               │                   that target is located outside the root. This only applies
│                               │                   to operations where the last path component is a junction
│                               │                   (path/to/junction, but not path/junction/target). 
│                               ├ Severity        : LOW 
│                               ├ CweIDs                   
│                               │                  ────────
│                               │                  CWE-1386
│                               ├ VendorSeverity   ╭ bitnami: 4 
│                               │                  ├ photon : 4 
│                               │                  ├ redhat : 1 
│                               │                  ╰ ubuntu : 2 
│                               ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I
│                               │                  │         │           :H/A:H 
│                               │                  │         ╰ V3Score : 9.8 
│                               │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I
│                               │                            │           :L/A:N 
│                               │                            ╰ V3Score : 3.3 
│                               ├ References                                                                
│                               │                  ─────────────────────────────────────────────────────────
│                               │                  https://access.redhat.com/security/cve/CVE-2026-56857    
│                               │                  https://github.com/golang/go/issues/81739                
│                               │                  https://go.dev/cl/847305                                 
│                               │                  https://go.dev/issue/81739                               
│                               │                  https://groups.google.com/g/golang-announce/c/U2fTuyDJznI
│                               │                  https://nvd.nist.gov/vuln/detail/CVE-2026-56857          
│                               │                  https://pkg.go.dev/vuln/GO-2026-6604                     
│                               │                  https://www.cve.org/CVERecord?id=CVE-2026-56857          
│                               │                  https://www.openwall.com/lists/oss-security/2026/10/08/9 
│                               ├ PublishedDate   : 2026-10-08T23:17:01.487Z 
│                               ╰ LastModifiedDate: 2026-10-09T16:35:35.9Z 
├ [16] ╭ Target         : usr/share/grafana/data/plugins-bundled/opentsdb/gpx_grafana-opentsdb-datasource_linux
│      │                  _amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : 28fc15a6b7634778 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:5efbce22d89d2d598cf1ccdb5861476217929c20ccebbd5814f61
│                        │     │                   b4281fa6cdf 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : 28fc15a6b7634778 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:91e9f7e70e9917a98c2000ad5ff91148db990aedb5c8ad2eef763
│                        │     │                   c6c314c4504 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [2] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : 52c09fc8b7fb6f6f 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:71566b0a7703663663e554f59f157d9fe49cc3bb764cf1f69781d
│                              │                   6c55d2caeb6 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [17] ╭ Target         : usr/share/grafana/data/plugins-bundled/prometheus/gpx_grafana-prometheus-datasource_l
│      │                  inux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : ad9b3fa173561cc8 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:793e251afa3b9d0d9bd16bbc46c67639588fb7c0dac6ec2102a83
│                        │     │                   1221e74c756 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : ad9b3fa173561cc8 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:6d1755dc8b3eb122efe29f7a4ae67c4c9c8979774e30cdd30538a
│                        │     │                   59ef8fc2148 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [2] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : ce4af04ba0ce8c57 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:9b56505cbad73666142a86d736b55389ae06cad8c4ed600fcb62e
│                              │                   3479e4e8fe0 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [18] ╭ Target         : usr/share/grafana/data/plugins-bundled/stackdriver/gpx_grafana_cloudmonitoring_dataso
│      │                  urce_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-128085 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-q7gw-24fr-5p69
│                        │     ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.45.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/sdk 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.45.0 
│                        │     │                  ╰ UID : b5e9ce21687e7607 
│                        │     ├ InstalledVersion: v1.45.0 
│                        │     ├ FixedVersion    : 1.47.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:0893711d79f9fcf835034bdb526449b5e1fdfe7a0985198a40d6a
│                        │     │                   969ba9f8d44 
│                        │     ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │     │                   go.opentelemetry.io/otel/sdk/log:
│                        │     │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │     │                   Service via attribute truncation bypass using Unicode
│                        │     │                   replacement characters 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │     │                   version 1.35.0 until version 1.47.0, the
│                        │     │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │     │                   truncation paths in sdk/internal/attrnorm,
│                        │     │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │     │                   valid U+FFFD replacement characters. This is a distinct
│                        │     │                   incomplete-fix defect in the replacement truncation code
│                        │     │                   introduced by the remediation for CVE-2026-81869. Values
│                        │     │                   composed of or dominated by those characters can therefore
│                        │     │                   exceed the configured character and memory bound in span,
│                        │     │                   log-record, and auto-instrumentation trace attributes.
│                        │     │                   Attacker-controlled telemetry attributes can increase
│                        │     │                   retained memory and pipeline pressure, while confidentiality
│                        │     │                    and integrity are not affected. This issue is fixed in
│                        │     │                   version 1.47.0. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-135
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:L 
│                        │     │                  │        ╰ V3Score : 5.3 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-128085       
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-128085              
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/commit/017
│                        │     │                  b08c7f1018b619991aaf6b2299d4beb9da1d3                        
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/log/v1.47.0                                           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/v1.47.0                                               
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/trace/v1.47.0                                             
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/security/a
│                        │     │                  dvisories/GHSA-q7gw-24fr-5p69                                
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085             
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-128085             
│                        │     ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │     ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-128085 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-q7gw-24fr-5p69
│                        │     ├ PkgID           : go.opentelemetry.io/otel/trace@v1.46.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/trace 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/trace@v1.46.0 
│                        │     │                  ╰ UID : 527ab5acf190d612 
│                        │     ├ InstalledVersion: v1.46.0 
│                        │     ├ FixedVersion    : 1.47.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-128085 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:f5a2cbe8a8adcd8bea09fa2d03716416ed5dfd2bc84131aa8a1c5
│                        │     │                   0301324774d 
│                        │     ├ Title           : go.opentelemetry.io/otel/sdk:
│                        │     │                   go.opentelemetry.io/otel/sdk/log:
│                        │     │                   go.opentelemetry.io/otel/trace: OpenTelemetry-Go: Denial of
│                        │     │                   Service via attribute truncation bypass using Unicode
│                        │     │                   replacement characters 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From SDK version 1.33.0, SDK log version 0.9.0, and trace
│                        │     │                   version 1.35.0 until version 1.47.0, the
│                        │     │                   AttributeValueLengthLimit and WithAttributeValueLengthLimit
│                        │     │                   truncation paths in sdk/internal/attrnorm,
│                        │     │                   sdk/log/internal/attrnorm, and trace/auto.go do not count
│                        │     │                   valid U+FFFD replacement characters. This is a distinct
│                        │     │                   incomplete-fix defect in the replacement truncation code
│                        │     │                   introduced by the remediation for CVE-2026-81869. Values
│                        │     │                   composed of or dominated by those characters can therefore
│                        │     │                   exceed the configured character and memory bound in span,
│                        │     │                   log-record, and auto-instrumentation trace attributes.
│                        │     │                   Attacker-controlled telemetry attributes can increase
│                        │     │                   retained memory and pipeline pressure, while confidentiality
│                        │     │                    and integrity are not affected. This issue is fixed in
│                        │     │                   version 1.47.0. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-135
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:L 
│                        │     │                  │        ╰ V3Score : 5.3 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-128085       
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-128085              
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/commit/017
│                        │     │                  b08c7f1018b619991aaf6b2299d4beb9da1d3                        
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/log/v1.47.0                                           
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/sdk/v1.47.0                                               
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/releases/t
│                        │     │                  ag/trace/v1.47.0                                             
│                        │     │                  https://github.com/open-telemetry/opentelemetry-go/security/a
│                        │     │                  dvisories/GHSA-q7gw-24fr-5p69                                
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-128085             
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-128085             
│                        │     ├ PublishedDate   : 2026-11-13T19:19:31.193Z 
│                        │     ╰ LastModifiedDate: 2026-11-18T05:19:02.727Z 
│                        ├ [2] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.57.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.57.0 
│                        │     │                  ╰ UID : 45017f185bf42387 
│                        │     ├ InstalledVersion: v0.57.0 
│                        │     ├ FixedVersion    : 0.58.1-0.20261009181718-2f1f834330b2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:77434c7838127fa390e5ad4bd6bc6fddd2d2960901c75cd39f7ae
│                        │     │                   b8ae3cdcafd 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References                                           
│                        │                        ────────────────────────────────────
│                        │                        https://go.dev/issue/44226          
│                        │                        https://go.dev/issue/81227          
│                        │                        https://pkg.go.dev/vuln/GO-2026-5932
│                        ├ [3] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.60.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.60.0 
│                        │     │                  ╰ UID : 956e4eb947e2abaa 
│                        │     ├ InstalledVersion: v0.60.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:085a3000ae6e779a0c55940d24aea97798960e819719e28d5d4f3
│                        │     │                   e2fe39decfb 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [4] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.60.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.60.0 
│                        │     │                  ╰ UID : 956e4eb947e2abaa 
│                        │     ├ InstalledVersion: v0.60.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:f6330ff2b462a535100010a2698ba4e93dc0ffc95081f92c24a00
│                        │     │                   67017e980c4 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [5] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : f0c39c3481aefdd7 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:f2f4001034e4b7a96c6853e3abd1e9bfd9b63df3f01781eae9f25
│                              │                   5a29cbe6358 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
├ [19] ╭ Target         : usr/share/grafana/data/plugins-bundled/tempo/gpx_grafana-tempo-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-21728 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-p4r4-xvrq-gvmc
│                        │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260910130453-bcfe9f230c1d 
│                        │     ├ PkgName         : github.com/grafana/tempo 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20260910
│                        │     │                  │       130453-bcfe9f230c1d 
│                        │     │                  ╰ UID : 26dcfea292072616 
│                        │     ├ InstalledVersion: v1.5.1-0.20260910130453-bcfe9f230c1d 
│                        │     ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:6a706f90502a0029b9815538148f70f4e380ef4330fce796d7bb4
│                        │     │                   93013018dbf 
│                        │     ├ Title           : grafana/tempo: Tempo: Denial of Service via large queries 
│                        │     ├ Description     : Tempo queries with large limits can cause large memory
│                        │     │                   allocations which can impact the availability of the
│                        │     │                   service, depending on its deployment strategy.
│                        │     │                   
│                        │     │                   Mitigation can be done by setting max_result_limit in the
│                        │     │                   search config, e.g. to 262144 (2^18). Alternatively,
│                        │     │                   automatically restart the service. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-400
│                        │     │                  CWE-770
│                        │     ├ VendorSeverity   ╭ ghsa  : 3 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:H 
│                        │     │                  │        ╰ V3Score : 7.5 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References       ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     │                  ...
│                        │     ├ PublishedDate   : 2026-04-24T09:16:03.71Z 
│                        │     ╰ LastModifiedDate: 2026-10-26T21:10:00.17Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-28377 
│                        │     ├ VendorIDs                           
│                        │     │                  ───────────────────
│                        │     │                  GHSA-ffqx-q65f-36jf
│                        │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260910130453-bcfe9f230c1d 
│                        │     ├ PkgName         : github.com/grafana/tempo 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20260910
│                        │     │                  │       130453-bcfe9f230c1d 
│                        │     │                  ╰ UID : 26dcfea292072616 
│                        │     ├ InstalledVersion: v1.5.1-0.20260910130453-bcfe9f230c1d 
│                        │     ├ FixedVersion    : 2.10.3 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:181db3258c2c4afb3902ee82b2f85e482daff85d2cc2e833c0cc3
│                        │     │                   ac099f77c13 
│                        │     ├ Title           : Grafana Tempo: Grafana Tempo: Information disclosure of S3
│                        │     │                   encryption key via status config endpoint 
│                        │     ├ Description     : A vulnerability in Grafana Tempo exposes the S3 SSE-C
│                        │     │                   encryption key in plaintext through the /status/config
│                        │     │                   endpoint, potentially allowing unauthorized users to obtain
│                        │     │                   the key used to encrypt trace data stored in S3.
│                        │     │                   
│                        │     │                   Thanks to william_goodfellow for reporting this
│                        │     │                   vulnerability. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-326
│                        │     ├ VendorSeverity   ╭ ghsa  : 3 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N
│                        │     │                  │        │           /A:N 
│                        │     │                  │        ╰ V3Score : 7.5 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.5 
│                        │     ├ References                                                                    
│                        │     │                  ─────────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-28377        
│                        │     │                  https://github.com/advisories/GHSA-ffqx-q65f-36jf            
│                        │     │                  https://github.com/grafana/tempo                             
│                        │     │                  https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b67498b6
│                        │     │                  62b85a148698b4afd/CHANGELOG.md?plain=1#L135                  
│                        │     │                  https://github.com/grafana/tempo/commit/bb8ca663db34a0980c975
│                        │     │                  8b40d918fda3b4dbec3                                          
│                        │     │                  https://grafana.com/security/security-advisories/cve-2026-283
│                        │     │                  77                                                           
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-28377              
│                        │     │                                                                               
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-28377              
│                        │     ├ PublishedDate   : 2026-03-26T22:16:28.46Z 
│                        │     ╰ LastModifiedDate: 2026-06-17T13:20:14.76Z 
│                        ├ [2] ╭ VulnerabilityID : CVE-2026-78661 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6860
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : 1d5dfd1a67b02f71 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:87ebb670404f14d87ceb34acc594ac71fc316c60e0a50cb1fa2fe
│                        │     │                   1a72be5527f 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
│                        │     │                   Service via crafted HTML input 
│                        │     ├ Description     : When coalescing adjacent text nodes in addText and
│                        │     │                   fosterParent, appending to an existing TextNode's Data via
│                        │     │                   string concatenation (n.Data += text) reallocated and copied
│                        │     │                    the accumulated string on every token. Inputs containing
│                        │     │                   many short text runs separated by ignored end tags (such as
│                        │     │                   "a</x>") caused O(n^2) allocations and byte copies.
│                        │     │                   Accumulate coalesced text in per-node byte slices during
│                        │     │                   parsing and materialize Data strings once at the end of
│                        │     │                   parse. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs                  
│                        │     │                  ───────
│                        │     │                  CWE-407
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
│                        │     │                  https://go.dev/cl/849365                                 
│                        │     │                  https://go.dev/issue/82224                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
│                        │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
│                        ├ [3] ╭ VulnerabilityID : CVE-2026-97045 
│                        │     ├ VendorIDs                    
│                        │     │                  ────────────
│                        │     │                  GO-2026-6866
│                        │     ├ PkgID           : golang.org/x/net@v0.61.0 
│                        │     ├ PkgName         : golang.org/x/net 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
│                        │     │                  ╰ UID : 1d5dfd1a67b02f71 
│                        │     ├ InstalledVersion: v0.61.0 
│                        │     ├ FixedVersion    : 0.62.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                        │     │                  │         a4bbba599de722a4416d 
│                        │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                        │     │                            20c0db24f65fbfa6dc9e 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:d0b1761c190731b462063c59d4497922c70cea3223704ef450309
│                        │     │                   464e7518141 
│                        │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
│                        │     │                   Scripting via improper namespace handling during HTML
│                        │     │                   rendering 
│                        │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
│                        │     │                   stopped at the nearest foreign ancestor once an HTML
│                        │     │                   integration point was found. However, that integration point
│                        │     │                    may itself be a descendant of an element that was
│                        │     │                   foster-parented into a foreign namespace (such as <mglyph>
│                        │     │                   or <malignmark> fostered under <mtext>), causing a parser to
│                        │     │                    resolve the subtree in a different foreign namespace upon
│                        │     │                   re-parsing the rendered output. Continue walking the full
│                        │     │                   ancestor chain and verify that every transition from a
│                        │     │                   non-empty namespace occurs at an HTML integration point
│                        │     │                   before emitting literal text. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs                 
│                        │     │                  ──────
│                        │     │                  CWE-79
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 6.1 
│                        │     ├ References                                                                
│                        │     │                  ─────────────────────────────────────────────────────────
│                        │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
│                        │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
│                        │     │                  https://go.dev/cl/855121                                 
│                        │     │                  https://go.dev/issue/82622                               
│                        │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
│                        │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
│                        │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
│                        │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
│                        │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
│                        │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
│                        ╰ [4] ╭ VulnerabilityID : CVE-2026-97054 
│                              ├ VendorIDs                    
│                              │                  ────────────
│                              │                  GO-2026-6859
│                              ├ PkgID           : stdlib@v1.27.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
│                              │                  ╰ UID : 227ea72f486f7562 
│                              ├ InstalledVersion: v1.27.3 
│                              ├ FixedVersion    : 1.26.11, 1.27.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
│                              │                  │         a4bbba599de722a4416d 
│                              │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
│                              │                            20c0db24f65fbfa6dc9e 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:61944a11d385da8e9c3d59ddde623a4b9b047682e62b10ec838a5
│                              │                   9d75e8ddbd1 
│                              ├ Title           : net/http: golang: net/http: Denial of Service via race
│                              │                   condition when handling oversized HTTP/1 requests 
│                              ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
│                              │                    "Connection: close" header is automatically set without
│                              │                   synchronization, which might race with another header being
│                              │                   set explicitly in the server handler. As a result, an HTTP/1
│                              │                    server that utilizes MaxBytesReader or MaxBytesHandler can
│                              │                   crash due to runtime panic if its handler reads the request
│                              │                   body concurrently with writing the response header. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs                  
│                              │                  ───────
│                              │                  CWE-362
│                              │                  CWE-820
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References                                                                    
│                              │                  ─────────────────────────────────────────────────────────────
│                              │                  https://access.redhat.com/errata/RHSA-2026:102586            
│                              │                  https://access.redhat.com/errata/RHSA-2026:102587            
│                              │                  https://access.redhat.com/security/cve/CVE-2026-97054        
│                              │                  https://bugzilla.redhat.com/2571442                          
│                              │                  https://bugzilla.redhat.com/2571443                          
│                              │                  https://bugzilla.redhat.com/2571444                          
│                              │                  https://bugzilla.redhat.com/2571445                          
│                              │                  https://bugzilla.redhat.com/2571446                          
│                              │                  https://bugzilla.redhat.com/2571447                          
│                              │                  https://bugzilla.redhat.com/2571448                          
│                              │                  https://bugzilla.redhat.com/2571449                          
│                              │                  https://bugzilla.redhat.com/2571450                          
│                              │                  https://bugzilla.redhat.com/2571451                          
│                              │                  https://bugzilla.redhat.com/2571452                          
│                              │                  https://bugzilla.redhat.com/2571453                          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
│                              │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
│                              │                  https://creativecommons.org/licenses/by/4.0/                 
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
│                              │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
│                              │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
│                              │                  https://errata.rockylinux.org/RLSA-2026:102586               
│                              │                  https://go.dev/cl/862185                                     
│                              │                  https://go.dev/issue/82563                                   
│                              │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
│                              │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
│                              │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
│                              │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
│                              │                  https://pkg.go.dev/vuln/GO-2026-6859                         
│                              │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
│                              ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
│                              ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
╰ [20] ╭ Target         : usr/share/grafana/data/plugins-bundled/zipkin/gpx_grafana-zipkin-datasource_linux_amd64 
       ├ Class          : lang-pkgs 
       ├ Type           : gobinary 
       ├ Packages        
       ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-78661 
                         │     ├ VendorIDs                    
                         │     │                  ────────────
                         │     │                  GO-2026-6860
                         │     ├ PkgID           : golang.org/x/net@v0.61.0 
                         │     ├ PkgName         : golang.org/x/net 
                         │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
                         │     │                  ╰ UID : eb2d18e2c4c415d 
                         │     ├ InstalledVersion: v0.61.0 
                         │     ├ FixedVersion    : 0.62.0 
                         │     ├ Status          : fixed 
                         │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
                         │     │                  │         a4bbba599de722a4416d 
                         │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
                         │     │                            20c0db24f65fbfa6dc9e 
                         │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78661 
                         │     ├ DataSource       ╭ ID  : govulndb 
                         │     │                  ├ Name: The Go Vulnerability Database 
                         │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
                         │     ├ Fingerprint     : sha256:29ce1d6fcd457a34df86d4d0f0698520d883ac2ecf24504bf68b4
                         │     │                   15904bf0eda 
                         │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
                         │     │                   Service via crafted HTML input 
                         │     ├ Description     : When coalescing adjacent text nodes in addText and
                         │     │                   fosterParent, appending to an existing TextNode's Data via
                         │     │                   string concatenation (n.Data += text) reallocated and copied
                         │     │                    the accumulated string on every token. Inputs containing
                         │     │                   many short text runs separated by ignored end tags (such as
                         │     │                   "a</x>") caused O(n^2) allocations and byte copies.
                         │     │                   Accumulate coalesced text in per-node byte slices during
                         │     │                   parsing and materialize Data strings once at the end of
                         │     │                   parse. 
                         │     ├ Severity        : HIGH 
                         │     ├ CweIDs                  
                         │     │                  ───────
                         │     │                  CWE-407
                         │     ├ VendorSeverity   ╭ amazon: 3 
                         │     │                  ├ azure : 2 
                         │     │                  ╰ redhat: 3 
                         │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                         │     │                           │           /A:H 
                         │     │                           ╰ V3Score : 7.5 
                         │     ├ References                                                                
                         │     │                  ─────────────────────────────────────────────────────────
                         │     │                  https://access.redhat.com/security/cve/CVE-2026-78661    
                         │     │                  https://advisory.echohq.com/cve/CVE-2026-78661           
                         │     │                  https://go.dev/cl/849365                                 
                         │     │                  https://go.dev/issue/82224                               
                         │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
                         │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-78661          
                         │     │                  https://pkg.go.dev/vuln/GO-2026-6860                     
                         │     │                  https://www.cve.org/CVERecord?id=CVE-2026-78661          
                         │     ├ PublishedDate   : 2026-10-27T22:18:05.93Z 
                         │     ╰ LastModifiedDate: 2026-11-04T17:17:37.673Z 
                         ├ [1] ╭ VulnerabilityID : CVE-2026-97045 
                         │     ├ VendorIDs                    
                         │     │                  ────────────
                         │     │                  GO-2026-6866
                         │     ├ PkgID           : golang.org/x/net@v0.61.0 
                         │     ├ PkgName         : golang.org/x/net 
                         │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.61.0 
                         │     │                  ╰ UID : eb2d18e2c4c415d 
                         │     ├ InstalledVersion: v0.61.0 
                         │     ├ FixedVersion    : 0.62.0 
                         │     ├ Status          : fixed 
                         │     ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
                         │     │                  │         a4bbba599de722a4416d 
                         │     │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
                         │     │                            20c0db24f65fbfa6dc9e 
                         │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97045 
                         │     ├ DataSource       ╭ ID  : govulndb 
                         │     │                  ├ Name: The Go Vulnerability Database 
                         │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
                         │     ├ Fingerprint     : sha256:1b0d39cd7b4a49f5720c6bdc5e2cce36043d239692977aef8465a
                         │     │                   b660e95b92b 
                         │     ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
                         │     │                   Scripting via improper namespace handling during HTML
                         │     │                   rendering 
                         │     ├ Description     : In childTextNodesAreLiteral, walking up the tree previously
                         │     │                   stopped at the nearest foreign ancestor once an HTML
                         │     │                   integration point was found. However, that integration point
                         │     │                    may itself be a descendant of an element that was
                         │     │                   foster-parented into a foreign namespace (such as <mglyph>
                         │     │                   or <malignmark> fostered under <mtext>), causing a parser to
                         │     │                    resolve the subtree in a different foreign namespace upon
                         │     │                   re-parsing the rendered output. Continue walking the full
                         │     │                   ancestor chain and verify that every transition from a
                         │     │                   non-empty namespace occurs at an HTML integration point
                         │     │                   before emitting literal text. 
                         │     ├ Severity        : MEDIUM 
                         │     ├ CweIDs                 
                         │     │                  ──────
                         │     │                  CWE-79
                         │     ├ VendorSeverity   ╭ amazon: 3 
                         │     │                  ├ azure : 2 
                         │     │                  ╰ redhat: 2 
                         │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                         │     │                           │           /A:N 
                         │     │                           ╰ V3Score : 6.1 
                         │     ├ References                                                                
                         │     │                  ─────────────────────────────────────────────────────────
                         │     │                  https://access.redhat.com/security/cve/CVE-2026-97045    
                         │     │                  https://advisory.echohq.com/cve/CVE-2026-97045           
                         │     │                  https://go.dev/cl/855121                                 
                         │     │                  https://go.dev/issue/82622                               
                         │     │                  https://groups.google.com/g/golang-announce/c/sqrs2vTx_Xs
                         │     │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97045          
                         │     │                  https://pkg.go.dev/vuln/GO-2026-6866                     
                         │     │                  https://www.cve.org/CVERecord?id=CVE-2026-97045          
                         │     ├ PublishedDate   : 2026-10-27T22:19:22.613Z 
                         │     ╰ LastModifiedDate: 2026-11-04T17:17:38.33Z 
                         ╰ [2] ╭ VulnerabilityID : CVE-2026-97054 
                               ├ VendorIDs                    
                               │                  ────────────
                               │                  GO-2026-6859
                               ├ PkgID           : stdlib@v1.27.3 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.27.3 
                               │                  ╰ UID : 7182452de0c4fa6 
                               ├ InstalledVersion: v1.27.3 
                               ├ FixedVersion    : 1.26.11, 1.27.4 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:72da8c94d85de80bd82f22d5e52fffa61962a3d3f6c8
                               │                  │         a4bbba599de722a4416d 
                               │                  ╰ DiffID: sha256:e345278c19ceef216f940fe91f3012ee971e8f366873
                               │                            20c0db24f65fbfa6dc9e 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-97054 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:dbe5459b05bcb697d7a21c50edcbf2d4620190a8fea7c1f7651c3
                               │                   cc467fcdd0b 
                               ├ Title           : net/http: golang: net/http: Denial of Service via race
                               │                   condition when handling oversized HTTP/1 requests 
                               ├ Description     : For HTTP/1 servers, when MaxBytesReader's limit is exceeded,
                               │                    "Connection: close" header is automatically set without
                               │                   synchronization, which might race with another header being
                               │                   set explicitly in the server handler. As a result, an HTTP/1
                               │                    server that utilizes MaxBytesReader or MaxBytesHandler can
                               │                   crash due to runtime panic if its handler reads the request
                               │                   body concurrently with writing the response header. 
                               ├ Severity        : MEDIUM 
                               ├ CweIDs                  
                               │                  ───────
                               │                  CWE-362
                               │                  CWE-820
                               ├ VendorSeverity   ╭ alma       : 2 
                               │                  ├ amazon     : 2 
                               │                  ├ oracle-oval: 2 
                               │                  ├ photon     : 2 
                               │                  ├ redhat     : 2 
                               │                  ╰ rocky      : 2 
                               ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
                               │                           │           /A:H 
                               │                           ╰ V3Score : 5.9 
                               ├ References                                                                    
                               │                  ─────────────────────────────────────────────────────────────
                               │                  https://access.redhat.com/errata/RHSA-2026:102586            
                               │                  https://access.redhat.com/errata/RHSA-2026:102587            
                               │                  https://access.redhat.com/security/cve/CVE-2026-97054        
                               │                  https://bugzilla.redhat.com/2571442                          
                               │                  https://bugzilla.redhat.com/2571443                          
                               │                  https://bugzilla.redhat.com/2571444                          
                               │                  https://bugzilla.redhat.com/2571445                          
                               │                  https://bugzilla.redhat.com/2571446                          
                               │                  https://bugzilla.redhat.com/2571447                          
                               │                  https://bugzilla.redhat.com/2571448                          
                               │                  https://bugzilla.redhat.com/2571449                          
                               │                  https://bugzilla.redhat.com/2571450                          
                               │                  https://bugzilla.redhat.com/2571451                          
                               │                  https://bugzilla.redhat.com/2571452                          
                               │                  https://bugzilla.redhat.com/2571453                          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571442          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571443          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571444          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571445          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571446          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571447          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571448          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571449          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571450          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571451          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571452          
                               │                  https://bugzilla.redhat.com/show_bug.cgi?id=2571453          
                               │                  https://creativecommons.org/licenses/by/4.0/                 
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97033
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97034
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97035
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97036
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97037
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97038
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97039
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97040
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97041
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97042
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97043
                               │                  https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-97054
                               │                  https://errata.almalinux.org/10/ALSA-2026-102587.html        
                               │                  https://errata.rockylinux.org/RLSA-2026:102586               
                               │                  https://go.dev/cl/862185                                     
                               │                  https://go.dev/issue/82563                                   
                               │                  https://groups.google.com/g/golang-announce/c/iY8TY0wWgbM    
                               │                  https://linux.oracle.com/cve/CVE-2026-97054.html             
                               │                  https://linux.oracle.com/errata/ELSA-2026-102587.html        
                               │                  https://nvd.nist.gov/vuln/detail/CVE-2026-97054              
                               │                  https://pkg.go.dev/vuln/GO-2026-6859                         
                               │                  https://www.cve.org/CVERecord?id=CVE-2026-97054              
                               ├ PublishedDate   : 2026-11-11T05:19:58.943Z 
                               ╰ LastModifiedDate: 2026-11-16T16:17:56.29Z 
```

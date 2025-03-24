# JFR assisted usage

---

## 🟢 Start a JFR recording given a PID

```bash
jfrOps.yaml op=start pid=1234 filename=record-1
```

or

```bash
jcmd 1234 JFR.start
```

---

## 🛑 Stop a JFR recording given a PID

```bash
jfrOps.yaml op=stop pid=1234 filename=record-1
```

or

```bash
jcmd 1234 JFR.stop
```

---

## 📋 Check existing JFR recordings for a PID

```bash
jfrOps.yaml op=view pid=1234
```

or

```bash
jcmd 1234 JFR.Check
```

---

## 💾 Copy the JFR recording for a PID to a local file

```bash
jfrOps.yaml op=copy pid=1234 filename=record-1 dumpFile=myrecording.jfr
```

> You can copy also directly from the original filesystem.

> Do take in consideration the filesystem space used in the original filesystem by each JFR recording.

--- 

## 📈 Check allocation by site

```bash
jfr view allocation-by-site record.jfr
```

You can also convert it to a CSV, if necesary:

```bash
jfr view allocation-by-site test.jfr | tail -n+4 | oafp in=lines linesvisual=true linesjoin=true out=ctable from="notStarts(Method, '--')"
```
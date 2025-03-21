# Examples

List of examples:

| Category | Example title |
|----------|---------------|
| Format | Output a Java GC JSON output from a Java GC log |
| Grafana | Visualize a Java GC log file in Grafana |
| Grafana | Get a Java GC log input into Grafana for visualization |
| Grafana | Get a live Java GC input into Grafana for visualization |
| Chart | Text chart with #threads, class loaders, heap and metaspace memory |
| Chart | Text table chart with the top 25 threads of a pid |
| Dashboard | Text-based dashboard regarding Java memory and GC |

> To search for a specific example type '/Checking images content<ENTER>' and use the arrow keys to navigate

---

## 📝 Output a Java GC JSON output from a Java GC log

### For Java (>8)

Start Java (>8) with the unified GC log:

```bash
java -Xlog:gc*:file=gc.log -jar myapp.jar 
```

> You can add timestamps by using ```-Xlog:gc*:file=gc.log:time```

Convert the unified GC log with oafp:

```bash
# oafp in=javagc gc.log out=ctable javagcjoin=true
oafp in=javagc gc.log out=btree javagcjoin=true out=ndjson | oafp in=ndjson ndjsonjoin=true out=ctable sql="select * where gcType <> 'none'"
```

### For Java 8

Start Java with GC log:

```bash
java -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintTenuringDistribution -XX:+PrintHeapAtGC -Xloggc:gc.log -jar myapp.jar
```

Convert the GC log with oafp:

```bash
oafp in=javagc gc.log out=ctable javagcjoin=true
```

---

## 📈 Get a Java GC log input into Grafana for visualization 

Execute:

```bash
oafp in=javagc gcout.txt out=openmetrics metricsprefix=java8 metricstimestamp=timestamp path="[]" | sed '/^$/d' > data.openmetrics
openmetrics2prom.sh data.openmetrics
rm data.openmetrics
```

> Don't forget to start nmaguiar/gcutils exposing the Grafana port 3000: ```docker run --rm -ti -p 3000:3000 nmaguiar/gcutils /bin/bash```

---

## 📈 Get a live Java GC input into Grafana for visualization 

1. Start Prometheus and Grafana

```bash
start_prom_graf.sh
```

2. Select a prefix to use and preload a Grafana dashboard

Let's select the prefix 'myjava':

```bash
curl -X POST -d "$(oafp cmd='grafana_gc.yaml prefix=myjava' outkey=dashboard out=json)" -H "Content-Type: application/json" http://localhost:3000/api/dashboards/db
```

3. Identify the Java PID you want to monitor

```bash
ps -axf
```

4. Start collecting Java GC data and send it live to Prometheus + Grafana with the choosen prefix

```bash
collect4pid.yaml pid=1105 prefix=myjava
```

> Don't forget to start nmaguiar/gcutils exposing the Grafana port 3000: ```docker run --rm -ti -p 3000:3000 nmaguiar/gcutils /bin/bash```

---

## 🗄️ Visualize a Java GC log file in Grafana

If no timestamp is provided:

```bash
oafp in=javagc gc.log out=json | oafp in=ndjson path="[].insert(@, 'timestamp', to_date(now(mul(sinceStart,\`-1000\`))))" out=openmetrics metricstimestamp=timestamp metricsprefix=java > data.openmetrics
openmetrics2prom.sh data.openmetrics
rm data.openmetrics
```

If a timestamp is provided:

```bash
oafp in=javagc gc.log out=outmetrics metricsprefix=java8 metricstimestamp=timestamp > data.openmetrics
openmetrics2prom.sh data.openmetrics
rm data.openmetrics
```

---

## 📝 Text chart with #threads, class loaders, heap and metaspace memory

Provides a text-based chart with the number of threads, class loaders, heap memory and metaspace memory:

```bash
USER=openaf && PID=1234 && HSPERF=/tmp/hsperfdata_$USER/$PID && oafp $HSPERF in=hsperf path=java out=grid grid="[[(title:Threads,type:chart,obj:'int threads.live:green:live threads.livePeak:red:peak threads.daemon:blue:daemon -min:0')|(title:Class Loaders,type:chart,obj:'int cls.loadedClasses:blue:loaded cls.unloadedClasses:red:unloaded')]|[(title:Heap,type:chart,obj:'bytes __mem.total:red:total __mem.used:blue:used -min:0')|(title:Metaspace,type:chart,obj:'bytes __mem.metaTotal:blue:total __mem.metaUsed:green:used -min:0')]]" loop=1
```

---

## 📊 Text table chart with the top 25 threads of a pid

Loops betweeh table updates of the 25 top most cpu active threads of the provided pid:

```bash
JPID=12345 && oafp cmd="ps -L -p $JPID -o tid,pcpu,comm|tail +2" in=lines linesjoin=true path="[].split_re(@,'\s+').{tid:[0],thread:join(' ',[2:]),cpu:to_number(nvl([1],\`-1\`)),cpuPerc:progress(nvl(to_number([1]),\`0\`), \`100\`, \`0\`, \`50\`, __, __)}" sql='select * order by cpu desc limit 25' out=ctable loop=1 loopcls=true
```

---

## 🎛️ Text-based dashboard regarding Java memory and GC

Provides a text-based dashboard regarding a target pid Java memory and GC:

```bash
javaGC.yaml pid=1234
```

---
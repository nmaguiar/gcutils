# Examples

List of examples:

| Category | Example title |
|----------|---------------|
| Grafana | Get a Java GC log input into Grafana for visualization |
| Grafana | Get a live Java GC input into Grafana for visualization |

> To search for a specific example type '/Checking images content<ENTER>' and use the arrow keys to navigate

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

---j
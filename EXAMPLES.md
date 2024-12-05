# Examples

## Get a Java GC log input into Grafana for visualization

Execute:

```bash
oafp in=javagc gcout.txt out=openmetrics metricsprefix=java8 metricstimestamp=timestamp path="[]" | sed '/^$/d' > data.openmetrics
openmetrics2prom.sh data.openmetrics
rm data.openmetrics
```
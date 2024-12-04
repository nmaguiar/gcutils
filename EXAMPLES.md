# Examples

## Get a Java GC log input into Grafana for visualization

Execute:

```bash
oafp in=javagc gcout.txt out=openmetrics metricsprefix=java8 metricstimestamp=$(date +%s) path="[].delete(nvl(@,from_json('{}')),'timestamp')" | sed '/^$/d' > data.openmetrics
echo "# EOF" >> data.openmetrics
sudo -u prometheus promtool tsdb create-blocks-from openmetrics data.openmetrics /usr/share/prometheus/data
rm data.openmetrics
```
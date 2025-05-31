#!/bin/bash

# Start prometheus and grafana
echo "Starting Prometheus and Grafana..."
sudo mkdir -p /var/log && sudo touch /var/log/prometheus.log && sudo touch /var/log/grafana.log
sudo chown -R openaf: /var/log/prometheus.log
sudo chown -R openaf: /var/log/grafana.log
/bin/bash -c "cd /usr/share/prometheus && nohup prometheus --config.file=/etc/prometheus.yml 2>&1 > /var/log/prometheus.log" &
/bin/bash -c "nohup bash -c 'export GF_AUTH_ANONYMOUS_ENABLED=true && export GF_AUTH_ANONYMOUS_ORG_ROLE=Admin && grafana server -homepath /usr/share/grafana' 2>&1 > /var/log/grafana.log" &


echo "Wait for Grafana to start..."
# Wait for Grafana to start
while true; do
  # Check if Grafana is running
  if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:3000" | grep -q "200"; then
    echo "Grafana is running!"
    break
  fi
done

echo "Adding Prometheus as a datasource to Grafana..."
# Add Prometheus as a datasource
curl -s -X POST http://127.0.0.1:3000/api/datasources -H 'Content-Type: application/json'  -d '{"name":"prometheus","type":"prometheus","url":"http://127.0.0.1:9090","access":"proxy","isDefault":true}'
echo ""

echo ""
echo "  tail -f /var/log/prometheus.log"
echo "  tail -f /var/log/grafana.log"
echo ""
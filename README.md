# prometheus-netscaler-sd

Provides Prometheus a list of targets via HTTP service discovery by querying the Nitro API. Basic authentication is used to pass the credentials along to the Nitro API.

## Run container
```
docker run --name=prometheus-netscaler-sd --restart unless-stopped -d -p 3005:3000 lspiehler/prometheus-netscaler-sd:latest
```

## Configure Prometheus
Example to scrape Netscaler targets
```
- job_name: interfaces
    metrics_path: /probe
    params:
      module: [tls_connect]
    http_sd_configs:
      - url: "http://prometheus-netscaler-sd:3000/netscaler?target="
        basic_auth:
          username: <netscaler_user>
          password: <netscaler_password>
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - source_labels: [hostname]
        target_label: __param_hostname
      - source_labels: [__param_hostname]
        target_label: hostname
      - target_label: __address__
        replacement: blackbox_exporter-cert:9115
```
# Resilience metrics on the real CICIoMT2024 detector

Generated 2026-10-16T16:39:21.043031+00:00. What is measured, what is modelled and what is not measured at all is spelled out in `backend/app/evaluation/run_resilience_metrics.py`; the short version is repeated under each heading.

## Latency (measured, in-process compute only)

| Step | p50 | p95 | p99 | n |
|---|---|---|---|---|
| Risk + Policy decision path (per incident) | 0.016 ms | 0.025 ms | 0.053 ms | 3000 |
| Real detector, one flow | 0.765 ms | 0.969 ms | 1.393 ms | 300 |

Detector batch throughput: 32,311 flows/s (1000 flows in 30.9 ms).

Not included: LLM-agent latency (a live model would dominate; this pipeline runs a mock), network and queueing delay, and real device recovery time.

## Detection delay, counted in flows (measured)

For each attack capture in the official test split, flows before the detector's first alert, in file order. The rows carry no wall-clock timestamp, so this is flows, not seconds, and not attack-onset-to-alert (a capture may contain unlabelled pre-attack traffic).

| Capture class | Flows | First alert at flow | Flows alerted | Within 10 flows |
|---|---|---|---|---|
| ARP_Spoofing (ARP_Spoofing_test.pcap.csv) | 1,744 | 0 | 86.1% | yes |
| MQTT-DDoS-Connect_Flood (MQTT-DDoS-Connect_Flood_test.pcap.csv) | 41,916 | 0 | 100.0% | yes |
| MQTT-DDoS-Publish_Flood (MQTT-DDoS-Publish_Flood_test.pcap.csv) | 8,416 | 0 | 74.5% | yes |
| MQTT-DoS-Connect_Flood (MQTT-DoS-Connect_Flood_test.pcap.csv) | 3,131 | 0 | 100.0% | yes |
| MQTT-DoS-Publish_Flood (MQTT-DoS-Publish_Flood_test.pcap.csv) | 8,505 | 0 | 100.0% | yes |
| MQTT-Malformed_Data (MQTT-Malformed_Data_test.pcap.csv) | 1,747 | 0 | 93.1% | yes |
| Recon-OS_Scan (Recon-OS_Scan_test.pcap.csv) | 3,834 | 0 | 88.8% | yes |
| Recon-Ping_Sweep (Recon-Ping_Sweep_test.pcap.csv) | 186 | 0 | 88.7% | yes |
| Recon-Port_Scan (Recon-Port_Scan_test.pcap.csv) | 22,622 | 0 | 98.2% | yes |
| Recon-VulScan (Recon-VulScan_test.pcap.csv) | 1,034 | 0 | 73.6% | yes |
| TCP_IP-DDoS-ICMP (TCP_IP-DDoS-ICMP1_test.pcap.csv) | 154,007 | 0 | 99.9% | yes |
| TCP_IP-DDoS-ICMP (TCP_IP-DDoS-ICMP2_test.pcap.csv) | 195,692 | 0 | 100.0% | yes |
| TCP_IP-DDoS-SYN (TCP_IP-DDoS-SYN_test.pcap.csv) | 172,397 | 1 | 99.9% | yes |
| TCP_IP-DDoS-TCP (TCP_IP-DDoS-TCP_test.pcap.csv) | 182,598 | 1 | 99.9% | yes |
| TCP_IP-DDoS-UDP (TCP_IP-DDoS-UDP1_test.pcap.csv) | 205,654 | 0 | 100.0% | yes |
| TCP_IP-DDoS-UDP (TCP_IP-DDoS-UDP2_test.pcap.csv) | 156,416 | 0 | 99.9% | yes |
| TCP_IP-DoS-ICMP (TCP_IP-DoS-ICMP_test.pcap.csv) | 98,432 | 0 | 100.0% | yes |
| TCP_IP-DoS-SYN (TCP_IP-DoS-SYN_test.pcap.csv) | 98,595 | 0 | 100.0% | yes |
| TCP_IP-DoS-TCP (TCP_IP-DoS-TCP_test.pcap.csv) | 82,096 | 1 | 99.9% | yes |
| TCP_IP-DoS-UDP (TCP_IP-DoS-UDP_test.pcap.csv) | 137,553 | 0 | 100.0% | yes |

20 of 20 attack captures were alerted on; 20 within their first 10 flows, 20 within 100.

## Cost of human approval: who waits (measured shares, modelled delay)

Shares are measured on all 1,614,182 test rows with sampled device contexts. The delay columns are a model: pipeline time (measured above) plus the share of alerts that wait for a human times an ASSUMED approval time D. The repository has no measurement of D.

### All devices

| System | Real attacks | Missed by detector | Contained autonomously | Waiting for a human | Share of alerts waiting | Mean delay at D = 1 min / 5 min / 15 min / 60 min |
|---|---|---|---|---|---|---|
| detection_only | 1,576,575 | 4,424 | 0 | 1,572,151 | 100.0% | 60.0 s / 300.0 s / 900.0 s / 3600.0 s |
| fixed_response | 1,576,575 | 4,424 | 1,572,151 | 0 | 0.0% | 0.0 s / 0.0 s / 0.0 s / 0.0 s |
| full_system | 1,576,575 | 4,424 | 785,858 | 786,293 | 50.0% | 30.0 s / 150.0 s / 450.1 s / 1800.5 s |

### High-stakes devices only

| System | Real attacks | Missed by detector | Contained autonomously | Waiting for a human | Share of alerts waiting | Mean delay at D = 1 min / 5 min / 15 min / 60 min |
|---|---|---|---|---|---|---|
| detection_only | 262,923 | 708 | 0 | 262,215 | 100.0% | 60.0 s / 300.0 s / 900.0 s / 3600.0 s |
| fixed_response | 262,923 | 708 | 262,215 | 0 | 0.0% | 0.0 s / 0.0 s / 0.0 s / 0.0 s |
| full_system | 262,923 | 708 | 0 | 262,215 | 100.0% | 60.0 s / 300.0 s / 900.0 s / 3600.0 s |

## Reading this honestly

- `detection_only` never acts, so every alert waits for a human (a fully manual response). `fixed_response` contains every alert at once but acts autonomously on high-stakes devices, which is the unsafe behaviour the safety comparison measures. `full_system` is where the patient-aware cost shows up: on high-stakes devices every alert waits for a human by design, so the delay there is the approval time, not a pipeline cost; on the other devices about half of alerts wait.
- The modelled delay is dominated by the assumed D; the table is a way to see that trade-off, not a prediction of a hospital's response time.
- 3 device-context seeds were used; contexts are sampled, not observed.

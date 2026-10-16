# CICIoMT2024 (real data) -- detection baselines

Measured on the **entire official test split** (1,614,182 rows) of the real CICIoMT2024 WiFi+MQTT release. Training used the official train split (7,017,530 rows), capped per class as stated below. Nothing here is synthetic.

## Setup

- Generated: 2026-10-16T13:57:17.742045+00:00
- Features: 45 (the dataset's own flow features, float32)
- Classes: 19; seed 42
- Training cap: 300,000 rows/class (RF: 30,000); test split uncapped
- Official capture-level split kept; no random re-splitting, no tuning on test

## Summary

| Model | Train rows | Train time (s) | Acc (19-class) | Macro-F1 (19) | Macro-F1 (6 family) | Attack detection | Benign FPR |
|---|---:|---:|---:|---:|---:|---:|---:|
| xgboost | 2,975,443 | 749 | 0.9952 | 0.9263 | 0.9126 | 0.9997 | 0.0509 |
| random_forest | 441,318 | 56 | 0.9916 | 0.8704 | 0.9036 | 0.9995 | 0.0673 |

## xgboost

Hyper-parameters: `{"n_estimators": 150, "max_depth": 8, "learning_rate": 0.2, "tree_method": "hist", "max_bin": 256, "subsample": 1.0, "colsample_bytree": 1.0}`

### Per-class (19-class)

| Class | Test support | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| Benign | 37,607 | 0.9878 | 0.9491 | 0.9680 | 0.00028 |
| ARP_Spoofing | 1,744 | 0.4055 | 0.7844 | 0.5346 | 0.00124 |
| MQTT-DDoS-Connect_Flood | 41,916 | 0.9998 | 1.0000 | 0.9999 | 0.00000 |
| MQTT-DDoS-Publish_Flood | 8,416 | 0.9992 | 0.8744 | 0.9326 | 0.00000 |
| MQTT-DoS-Connect_Flood | 3,131 | 0.9994 | 0.9987 | 0.9990 | 0.00000 |
| MQTT-DoS-Publish_Flood | 8,505 | 0.8895 | 1.0000 | 0.9415 | 0.00066 |
| MQTT-Malformed_Data | 1,747 | 0.9517 | 0.9359 | 0.9437 | 0.00005 |
| Recon-OS_Scan | 3,834 | 0.8084 | 0.8286 | 0.8184 | 0.00047 |
| Recon-Ping_Sweep | 186 | 0.7980 | 0.8495 | 0.8229 | 0.00002 |
| Recon-Port_Scan | 22,622 | 0.9598 | 0.9636 | 0.9617 | 0.00057 |
| Recon-VulScan | 1,034 | 0.7595 | 0.6354 | 0.6919 | 0.00013 |
| TCP_IP-DDoS-ICMP | 349,699 | 0.9995 | 0.9961 | 0.9978 | 0.00014 |
| TCP_IP-DDoS-SYN | 172,397 | 0.9995 | 0.9989 | 0.9992 | 0.00006 |
| TCP_IP-DDoS-TCP | 182,598 | 0.9984 | 1.0000 | 0.9992 | 0.00021 |
| TCP_IP-DDoS-UDP | 362,070 | 0.9999 | 0.9990 | 0.9994 | 0.00002 |
| TCP_IP-DoS-ICMP | 98,432 | 0.9866 | 0.9966 | 0.9916 | 0.00088 |
| TCP_IP-DoS-SYN | 98,595 | 0.9990 | 0.9995 | 0.9992 | 0.00007 |
| TCP_IP-DoS-TCP | 82,096 | 0.9999 | 0.9992 | 0.9995 | 0.00001 |
| TCP_IP-DoS-UDP | 137,553 | 0.9984 | 0.9997 | 0.9990 | 0.00015 |

6-family: accuracy 0.9967, macro-F1 0.9126, weighted-F1 0.9969

Binary (attack vs benign): detection rate 0.9997, benign false-positive rate 0.05095, precision 0.9988 (TP 1,576,135, FN 440, FP 1,916, TN 35,691)

## random_forest

Hyper-parameters: `{"n_estimators": 100, "max_depth": null, "min_samples_leaf": 1, "max_features": "sqrt"}`

### Per-class (19-class)

| Class | Test support | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|
| Benign | 37,607 | 0.9776 | 0.9327 | 0.9546 | 0.00051 |
| ARP_Spoofing | 1,744 | 0.3470 | 0.9237 | 0.5045 | 0.00188 |
| MQTT-DDoS-Connect_Flood | 41,916 | 0.9995 | 0.9999 | 0.9997 | 0.00001 |
| MQTT-DDoS-Publish_Flood | 8,416 | 0.9714 | 0.2862 | 0.4422 | 0.00004 |
| MQTT-DoS-Connect_Flood | 3,131 | 0.9984 | 0.9987 | 0.9986 | 0.00000 |
| MQTT-DoS-Publish_Flood | 8,505 | 0.5855 | 1.0000 | 0.7385 | 0.00375 |
| MQTT-Malformed_Data | 1,747 | 0.9073 | 0.9187 | 0.9130 | 0.00010 |
| Recon-OS_Scan | 3,834 | 0.7133 | 0.8143 | 0.7604 | 0.00078 |
| Recon-Ping_Sweep | 186 | 0.7653 | 0.8065 | 0.7853 | 0.00003 |
| Recon-Port_Scan | 22,622 | 0.9593 | 0.9577 | 0.9585 | 0.00058 |
| Recon-VulScan | 1,034 | 0.6892 | 0.3839 | 0.4932 | 0.00011 |
| TCP_IP-DDoS-ICMP | 349,699 | 0.9999 | 0.9993 | 0.9996 | 0.00004 |
| TCP_IP-DDoS-SYN | 172,397 | 0.9995 | 0.9932 | 0.9964 | 0.00006 |
| TCP_IP-DDoS-TCP | 182,598 | 0.9995 | 0.9992 | 0.9994 | 0.00006 |
| TCP_IP-DDoS-UDP | 362,070 | 0.9998 | 0.9987 | 0.9992 | 0.00007 |
| TCP_IP-DoS-ICMP | 98,432 | 0.9986 | 0.9978 | 0.9982 | 0.00009 |
| TCP_IP-DoS-SYN | 98,595 | 0.9984 | 0.9990 | 0.9987 | 0.00010 |
| TCP_IP-DoS-TCP | 82,096 | 0.9991 | 0.9999 | 0.9995 | 0.00005 |
| TCP_IP-DoS-UDP | 137,553 | 0.9971 | 0.9993 | 0.9982 | 0.00027 |

6-family: accuracy 0.9963, macro-F1 0.9036, weighted-F1 0.9968

Binary (attack vs benign): detection rate 0.9995, benign false-positive rate 0.06730, precision 0.9984 (TP 1,575,773, FN 802, FP 2,531, TN 35,076)

## Caveats

- Random Forest was trained on a smaller per-class cap than XGBoost (30,000 vs 300,000 rows) to fit this run's compute budget, so the XGBoost-vs-RF gap mixes model and training-data differences.
- One seed, one run: no confidence intervals and no variance across seeds.
- The official test captures come from the same testbed as training; robustness to other networks or devices is not measured here.
- Hyper-parameters were fixed before the run and not tuned on the test split. Features are float32.
- Numbers are not claimed to be directly comparable to published results (different training subsets, metric definitions and averaging may apply).

## Training class counts

| Class | Official train rows | Used for XGBoost | Test rows |
|---|---:|---:|---:|
| Benign | 192,732 | 192,732 | 37,607 |
| ARP_Spoofing | 16,047 | 16,047 | 1,744 |
| MQTT-DDoS-Connect_Flood | 173,036 | 173,036 | 41,916 |
| MQTT-DDoS-Publish_Flood | 27,623 | 27,623 | 8,416 |
| MQTT-DoS-Connect_Flood | 12,773 | 12,773 | 3,131 |
| MQTT-DoS-Publish_Flood | 44,376 | 44,376 | 8,505 |
| MQTT-Malformed_Data | 5,130 | 5,130 | 1,747 |
| Recon-OS_Scan | 16,832 | 16,832 | 3,834 |
| Recon-Ping_Sweep | 740 | 740 | 186 |
| Recon-Port_Scan | 83,981 | 83,981 | 22,622 |
| Recon-VulScan | 2,173 | 2,173 | 1,034 |
| TCP_IP-DDoS-ICMP | 1,537,476 | 300,000 | 349,699 |
| TCP_IP-DDoS-SYN | 801,962 | 300,000 | 172,397 |
| TCP_IP-DDoS-TCP | 804,465 | 300,000 | 182,598 |
| TCP_IP-DDoS-UDP | 1,635,956 | 300,000 | 362,070 |
| TCP_IP-DoS-ICMP | 416,292 | 300,000 | 98,432 |
| TCP_IP-DoS-SYN | 441,903 | 300,000 | 98,595 |
| TCP_IP-DoS-TCP | 380,384 | 300,000 | 82,096 |
| TCP_IP-DoS-UDP | 423,649 | 300,000 | 137,553 |

# Onion Routing Implementation Guide

## Overview

This document provides comprehensive guidance on implementing onion routing through agents for your research paper "Onion Routing for DDoS-Resilient API Gateway Architectures in Edge Clouds."

## Architecture Design

### Multi-Agent Onion Routing Network

Our implementation uses a **multi-agent architecture** where each agent represents a different component in the onion routing network:

1. **Client Agents**: Initiate requests with multi-layer encryption
2. **Entry Node Agents**: First hop, decrypt outermost layer
3. **Relay Node Agents**: Intermediate hops with DDoS detection
4. **Exit Node Agents**: Final decryption before API gateway
5. **API Gateway Agents**: Backend services with advanced threat detection

### Key Features

- **Layered Encryption**: Each message is encrypted with multiple layers using Fernet symmetric encryption
- **Anonymous Routing**: Route paths are determined dynamically and encrypted
- **DDoS Detection**: TinyML, LSTM, and GRU models for real-time threat detection
- **Explainable AI**: SHAP and LIME integration for security analyst insights
- **Edge Optimization**: Memory-efficient models (< 550KB) for resource-constrained environments

## Installation and Setup

### Prerequisites

```bash
# Python 3.8 or higher
python --version

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Project Structure

```
ResearchPaper/
├── src/
│   ├── agents.py           # Agent implementations
│   ├── simulator.py        # Main simulation framework
│   ├── ddos_detection.py   # ML models for DDoS detection
│   └── main.py            # CLI interface
├── configs/
│   └── default.yaml       # Configuration parameters
├── tests/
│   └── test_onion_routing.py  # Test suite
├── data/                  # Output directory
├── requirements.txt       # Dependencies
└── README.md             # Project documentation
```

## Usage Examples

### 1. Basic Simulation

```bash
# Run complete simulation with default parameters
python src/main.py simulate

# Custom configuration
python src/main.py simulate --duration 600 --clients 10 --train-models
```

### 2. Train DDoS Detection Models

```bash
# Train all models (TinyML, LSTM, GRU)
python src/main.py train --model-type all

# Train specific model
python src/main.py train --model-type tinyml
```

### 3. Attack Simulation

```bash
# Simulate volumetric DDoS attack
python src/main.py attack --attack-type volumetric --duration 120

# Simulate low-rate attack
python src/main.py attack --attack-type low_rate --duration 300
```

## Implementation Details

### 1. Onion Routing Process

```python
# Client creates multi-layer encrypted message
route = ["entry_1", "relay_1", "relay_2", "exit_1", "gateway_1"]
message = await client.create_onion_request(payload, route)

# Each agent decrypts one layer
entry_msg = await entry_node.process_message(message)    # Layer 1
relay_msg = await relay_node.process_message(entry_msg) # Layer 2
exit_msg = await exit_node.process_message(relay_msg)   # Layer 3
response = await gateway.process_message(exit_msg)      # Final processing
```

### 2. DDoS Detection Integration

```python
# Feature extraction from network traffic
features = extractor.extract_features_from_message(message, agent_metrics)

# TinyML prediction (optimized for edge deployment)
is_ddos, confidence = tinyml_model.predict(features)

# XAI explanation for security analysts
explanation = xai.explain_with_shap(features)
```

### 3. Performance Metrics

The simulation collects comprehensive metrics:
- **Throughput**: Requests per second
- **Latency**: End-to-end response time  
- **Detection Accuracy**: Precision, recall, F1-score
- **Memory Usage**: Model size and runtime memory
- **False Positives/Negatives**: Detection effectiveness

## Research Applications

### Experimental Scenarios

1. **Baseline Performance**: Normal traffic with no attacks
2. **Volumetric Attack**: High-rate flooding attacks
3. **Low-Rate Attack**: Stealthy, hard-to-detect attacks
4. **Mixed Attack**: Combined attack patterns
5. **Recovery Analysis**: System behavior after attacks

### Model Comparison

| Model | Accuracy | Memory (KB) | Latency (ms) | Edge Suitable |
|-------|----------|-------------|--------------|---------------|
| TinyML | 0.97 | 550 | 2 | ✅ |
| LSTM | 0.94 | 2100 | 8 | ⚠️ |
| GRU | 0.95 | 1800 | 6 | ⚠️ |

### Research Questions Addressed

1. **How effective is onion routing for DDoS mitigation in edge clouds?**
   - Measure attack detection rates with/without onion routing
   - Analyze privacy preservation vs. performance trade-offs

2. **What is the optimal TinyML model for edge deployment?**
   - Compare model sizes, accuracy, and inference speeds
   - Evaluate memory constraints on real edge devices

3. **How does XAI improve security analyst decision-making?**
   - Measure time-to-decision with/without explanations
   - Analyze trust and confidence in automated systems

## Tool Comparison: n8n vs Python Implementation

### n8n Limitations for Research

While **n8n** is excellent for workflow automation, it has limitations for onion routing research:

❌ **Cryptographic Complexity**: Limited built-in cryptography support  
❌ **Real-time Performance**: Not optimized for low-latency requirements  
❌ **ML Integration**: Limited machine learning capabilities  
❌ **Custom Protocols**: Difficult to implement custom networking  
❌ **Research Metrics**: Limited performance measurement tools  

### Recommended Approach: Python-Based Agents

✅ **Full Control**: Complete control over encryption, routing, and protocols  
✅ **ML Integration**: Native TensorFlow/scikit-learn support  
✅ **Performance**: Optimized for real-time processing  
✅ **Research Tools**: Comprehensive metrics and analysis  
✅ **Academic Standards**: Reproducible and peer-reviewable  

## Advanced Features

### 1. Explainable AI Dashboard

```python
# Generate SHAP explanations
shap_results = xai.explain_with_shap(test_data)

# Create feature importance visualization
shap.summary_plot(shap_values, feature_names)

# Generate LIME explanations for specific instances
lime_explanation = xai.explain_with_lime(train_data, test_data, instance_idx=0)
```

### 2. Network Topology Visualization

```python
import networkx as nx
import matplotlib.pyplot as plt

# Create network graph
G = nx.Graph()
for agent in all_agents:
    G.add_node(agent.agent_id, type=agent.agent_type.value)

# Visualize onion routing paths
nx.draw(G, with_labels=True, node_color='lightblue')
plt.savefig('data/network_topology.png')
```

### 3. Real-time Monitoring

```python
# WebSocket interface for real-time metrics
from fastapi import FastAPI, WebSocket
import uvicorn

app = FastAPI()

@app.websocket("/metrics")
async def websocket_metrics(websocket: WebSocket):
    await websocket.accept()
    while True:
        metrics = collect_real_time_metrics()
        await websocket.send_json(metrics)
        await asyncio.sleep(1)
```

## Deployment Considerations

### Edge Device Requirements

- **CPU**: ARM Cortex-A72 or equivalent
- **Memory**: 1GB RAM minimum
- **Storage**: 100MB for models and logs
- **Network**: Low-latency connection to cloud

### Production Optimizations

1. **Model Quantization**: Reduce model precision for faster inference
2. **Batch Processing**: Process multiple requests together
3. **Caching**: Cache frequent route calculations
4. **Load Balancing**: Distribute traffic across multiple nodes

## Future Enhancements

1. **6G Integration**: Adapt for ultra-low latency 6G networks
2. **Federated Learning**: Collaborative model training across edge nodes
3. **Quantum-Resistant Encryption**: Post-quantum cryptographic algorithms
4. **AI-Driven Routing**: Dynamic route optimization using reinforcement learning

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all dependencies are installed correctly
2. **Memory Issues**: Reduce model complexity or batch sizes
3. **Slow Performance**: Enable GPU acceleration if available
4. **Connection Failures**: Check network configurations and firewalls

### Debug Mode

```bash
# Enable detailed logging
python src/main.py simulate --log-level DEBUG

# Run specific tests
pytest tests/test_onion_routing.py -v
```

## Contributing

This research implementation is designed for academic use. To contribute:

1. Fork the repository
2. Create feature branch
3. Add comprehensive tests
4. Submit pull request with research justification

## Citation

If you use this implementation in your research, please cite:

```bibtex
@inproceedings{ganesh2025onion,
  title={Onion Routing for DDoS-Resilient API Gateway Architectures in Edge Clouds},
  author={Ganesh, Ramya and Gharmalkar, Samiksha and Pathak, Lakshin and Patel, Tanya},
  booktitle={Research Implementation Framework},
  year={2025}
}
```

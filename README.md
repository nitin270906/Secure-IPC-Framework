# Secure IPC Framework

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-stable-green.svg)
![Security](https://img.shields.io/badge/security-AES256%20%7C%20HMAC-purple.svg)

A high-fidelity simulation and educational framework for demonstrating secure Inter-Process Communication (IPC) techniques. This project implements a React-based frontend dashboard that controls a Python/Java backend to demonstrate the flow of data through Pipes, Message Queues, and Shared Memory, secured by military-grade encryption and integrity checks.

## 🌟 Key Features

### 🛡️ Security First
*   **AES-256-GCM Encryption**: Payloads are encrypted using Authenticated Encryption to ensure confidentiality and authenticity.
*   **HMAC-SHA256 Signing**: Every packet carries a digital signature to prevent tampering (Man-in-the-Middle attacks).
*   **Zero-Trust Authentication**: Processes must perform a cryptographic handshake to receive a session token before accessing IPC channels.
*   **Access Control Lists (ACL)**: Granular permissions (Read/Write/Admin) enforced at the API gateway.

### 📡 IPC Primitives Supported
1.  **System V Message Queues**: Discrete message passing with priority support.
2.  **Named Pipes (FIFO)**: Unidirectional stream-based communication.
3.  **Shared Memory**: High-performance, direct memory access blocks for large payloads.

### 📊 Visualization
*   **Real-time Network Visualizer**: Watch packets move between Sender and Receiver.
*   **Packet Inspector**: dissect binary payloads to view headers, signatures, and encrypted bodies.
*   **Tamper Simulation**: Inject malicious data to test the system's integrity verification logic.

## 🏗️ Architecture

The system follows a strict Client-Server model where the Frontend acts as the Control Plane and the Backend acts as the System Supervisor.

```
React Client (Dashboard)  <--->  REST API (Security Gateway)  <--->  OS Kernel (IPC Resources)
```

## 🚀 Getting Started

### Prerequisites
*   Node.js v18+
*   Python 3.9+ OR Java JDK 11+

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/organization/secure-ipc-framework.git
    cd secure-ipc-framework
    ```

2.  **Frontend Setup**
    ```bash
    npm install
    npm start
    ```

3.  **Backend Setup (Python)**
    ```bash
    cd backend
    pip install flask flask-cors cryptography
    python server.py
    ```

## 🧪 Usage Examples

### Python: Sending a Secure Message via Shared Memory

```python
import requests

# 1. Authenticate
auth = requests.post('http://localhost:5000/api/auth', json={
    'process_id': 'proc_1', 
    'permissions': ['write']
}).json()

# 2. Send Message
response = requests.post('http://localhost:5000/api/send', json={
    'pid': 'proc_1',
    'token': auth['token'],
    'message': 'Secret Payload',
    'method': 'shared_memory',
    'encrypt': True
})

print(response.json())
```

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.

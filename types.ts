
export interface Log {
  type: 'success' | 'error' | 'info' | 'warning' | 'debug';
  message: string;
  timestamp: string;
}

export type IpcMethod = 'queue' | 'pipe' | 'shared_memory';
export type ActiveTab = 'demo' | 'monitoring' | 'python' | 'java' | 'docs';

export interface ChannelData {
  id: string;
  payload: string;
  signature: string;
  timestamp: number;
  encrypted: boolean;
  signed: boolean;
  method: IpcMethod;
  isTampered: boolean;
}

export interface SystemStats {
  sent: number;
  received: number;
  integrityErrors: number;
  tamperAttempts: number;
}

export const PYTHON_CODE = `"""
Secure IPC Backend Implementation
---------------------------------
Features:
1. AES-256-GCM Encryption
2. HMAC-SHA256 Message Integrity
3. IPC Primitives:
   - System V Message Queues (via multiprocessing)
   - Named Pipes (FIFO)
   - Shared Memory Blocks
"""

import os
import json
import time
import hmac
import hashlib
import base64
import struct
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from multiprocessing import Queue, shared_memory

app = Flask(__name__)
CORS(app)

# --- SECURITY LAYER ---

class SecurityContext:
    def __init__(self):
        # Generate a 256-bit key for AES-GCM
        self.master_key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.master_key)
        # Separate key for HMAC operations
        self.signing_key = os.urandom(32)
        self.active_tokens: Dict[str, dict] = {}

    def register_process(self, process_id: str, permissions: list) -> str:
        token = base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8')
        self.active_tokens[process_id] = {
            'token': token,
            'permissions': permissions,
            'created_at': time.time()
        }
        return token

    def verify_auth(self, process_id: str, token: str, required_perm: str = 'read') -> bool:
        session = self.active_tokens.get(process_id)
        if not session or session['token'] != token:
            return False
        if 'admin' in session['permissions']:
            return True
        return required_perm in session['permissions']

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)  # NIST recommended nonce size
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        # Return nonce + ciphertext as base64
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def decrypt(self, payload: str) -> str:
        raw = base64.b64decode(payload)
        nonce, ciphertext = raw[:12], raw[12:]
        return self.aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

    def sign(self, data: str) -> str:
        h = hmac.new(self.signing_key, data.encode('utf-8'), hashlib.sha256)
        return h.hexdigest()

    def verify_signature(self, data: str, signature: str) -> bool:
        expected = self.sign(data)
        return hmac.compare_digest(expected, signature)

# --- IPC ABSTRACTION LAYER ---

class IPCChannel(ABC):
    @abstractmethod
    def send(self, data: dict): pass

    @abstractmethod
    def receive(self) -> Optional[dict]: pass

class MessageQueueChannel(IPCChannel):
    """Implementation using Python's multiprocessing.Queue"""
    def __init__(self):
        self.queue = Queue()

    def send(self, data: dict):
        self.queue.put(data)

    def receive(self) -> Optional[dict]:
        if not self.queue.empty():
            return self.queue.get()
        return None

class NamedPipeChannel(IPCChannel):
    """Implementation using OS FIFO Pipes"""
    def __init__(self, pipe_path='/tmp/secure_ipc_pipe'):
        self.path = pipe_path
        if not os.path.exists(self.path):
            os.mkfifo(self.path)

    def send(self, data: dict):
        # Blocking write to pipe
        payload_bytes = json.dumps(data).encode('utf-8')
        # Write length prefix (4 bytes) + payload
        with open(self.path, 'wb') as p:
            p.write(struct.pack('>I', len(payload_bytes)) + payload_bytes)

    def receive(self) -> Optional[dict]:
        # In a real scenario, this would block or poll
        # Simplified for demo:
        try:
            # Logic to read specific bytes would go here
            pass
        except Exception:
            return None
        return None

class SharedMemoryChannel(IPCChannel):
    """Implementation using Shared Memory Blocks"""
    def __init__(self, name='secure_shm', size=4096):
        self.name = name
        self.size = size
        try:
            self.shm = shared_memory.SharedMemory(create=True, size=size, name=name)
        except FileExistsError:
            self.shm = shared_memory.SharedMemory(name=name)

    def send(self, data: dict):
        payload = json.dumps(data).encode('utf-8')
        if len(payload) > self.size:
            raise ValueError("Payload exceeds shared memory size")
        self.shm.buf[:len(payload)] = payload
        # Pad remaining with null bytes
        self.shm.buf[len(payload):] = b'\\0' * (self.size - len(payload))

    def receive(self) -> Optional[dict]:
        # Read until null byte
        data = bytes(self.shm.buf).split(b'\\0', 1)[0]
        if not data:
            return None
        return json.loads(data.decode('utf-8'))

# --- SERVER INIT ---

sec = SecurityContext()
channels = {
    'queue': MessageQueueChannel(),
    'pipe': NamedPipeChannel(), # Warning: Pipes block on open() without reader
    'shared_memory': SharedMemoryChannel()
}

@app.route('/api/auth', methods=['POST'])
def authenticate():
    pid = request.json.get('process_id')
    perms = request.json.get('permissions', ['read'])
    token = sec.register_process(pid, perms)
    return jsonify({'token': token, 'expiry': 3600})

@app.route('/api/send', methods=['POST'])
def send_msg():
    data = request.json
    
    # 1. Authentication
    if not sec.verify_auth(data['pid'], data['token'], 'write'):
        return jsonify({'error': 'Access Denied'}), 403

    payload = data['message']
    
    # 2. Encryption (Optional)
    if data.get('encrypt'):
        payload = sec.encrypt(payload)

    # 3. Signing (Mandatory)
    signature = sec.sign(payload)

    packet = {
        'payload': payload,
        'signature': signature,
        'timestamp': time.time(),
        'encrypted': data.get('encrypt', False)
    }

    # 4. Dispatch to IPC Channel
    method = data.get('method', 'queue')
    if method in channels:
        try:
            channels[method].send(packet)
            return jsonify({'status': 'queued', 'signature': signature})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return jsonify({'error': 'Invalid method'}), 400

if __name__ == '__main__':
    app.run(port=5000, debug=True)
`;

export const JAVA_CODE = `// SecureIPCController.java
package com.ipc.framework;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

@SpringBootApplication
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class SecureIPCController {
    
    private final SecurityManager securityManager = new SecurityManager();
    private final Map<String, BlockingQueue<IPCMessage>> messageQueues = 
        new ConcurrentHashMap<>();
    
    public static void main(String[] args) {
        SpringApplication.run(SecureIPCController.class, args);
    }
    
    @PostMapping("/authenticate")
    public AuthResponse authenticate(@RequestBody AuthRequest request) {
        String token = securityManager.registerProcess(
            request.getProcessId(), 
            request.getPermissions()
        );
        return new AuthResponse(true, token, request.getProcessId());
    }
    
    @PostMapping("/send")
    public SendResponse sendMessage(@RequestBody SendRequest request) {
        if (!securityManager.authenticate(request.getProcessId(), request.getToken())) {
            return new SendResponse(false, "Authentication failed", null);
        }
        
        String data = request.getMessage();
        if (request.isEncrypt()) {
            data = securityManager.encryptData(data);
        }
        
        String signature = securityManager.signMessage(data);
        
        String channelId = request.getProcessId() + "_" + request.getIpcMethod();
        messageQueues.putIfAbsent(channelId, new LinkedBlockingQueue<>());
        
        IPCMessage message = new IPCMessage(
            data, 
            signature, 
            System.currentTimeMillis(), 
            request.isEncrypt()
        );
        
        try {
            messageQueues.get(channelId).offer(message, 5, TimeUnit.SECONDS);
            return new SendResponse(true, "Message sent", signature);
        } catch (InterruptedException e) {
            return new SendResponse(false, "Queue full", null);
        }
    }
    
    @PostMapping("/receive")
    public ReceiveResponse receiveMessage(@RequestBody ReceiveRequest request) {
        if (!securityManager.authenticate(request.getProcessId(), request.getToken())) {
            return new ReceiveResponse(false, "Authentication failed", null);
        }
        
        String channelId = request.getProcessId() + "_" + request.getIpcMethod();
        BlockingQueue<IPCMessage> queue = messageQueues.get(channelId);
        
        if (queue == null || queue.isEmpty()) {
            return new ReceiveResponse(false, "No messages available", null);
        }
        
        try {
            IPCMessage message = queue.poll(1, TimeUnit.SECONDS);
            if (message != null) {
                if (message.isEncrypted()) {
                    message.setData(securityManager.decryptData(message.getData()));
                }
                return new ReceiveResponse(true, "Message received", message);
            }
            return new ReceiveResponse(false, "No messages", null);
        } catch (InterruptedException e) {
            return new ReceiveResponse(false, "Error receiving", null);
        }
    }
}

class SecurityManager {
    private final SecretKey encryptionKey;
    private final SecretKey hmacKey;
    private final Map<String, String> authTokens = new ConcurrentHashMap<>();
    private final Map<String, List<String>> permissions = new ConcurrentHashMap<>();
    
    public SecurityManager() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            this.encryptionKey = keyGen.generateKey();
            this.hmacKey = keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize security", e);
        }
    }
    
    public String registerProcess(String processId, List<String> perms) {
        String token = generateToken();
        authTokens.put(processId, token);
        permissions.put(processId, perms != null ? perms : 
            Arrays.asList("read", "write"));
        return token;
    }
    
    public boolean authenticate(String processId, String token) {
        return token.equals(authTokens.get(processId));
    }
    
    public String encryptData(String data) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            byte[] encrypted = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }
    
    public String decryptData(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
            byte[] decrypted = cipher.doFinal(
                Base64.getDecoder().decode(encryptedData)
            );
            return new String(decrypted);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
    
    public String signMessage(String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            byte[] signature = mac.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(signature);
        } catch (Exception e) {
            throw new RuntimeException("Signing failed", e);
        }
    }
    
    private String generateToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}

// DTOs
class IPCMessage {
    private String data;
    private String signature;
    private long timestamp;
    private boolean encrypted;
    
    // Constructors, getters, setters...
}
`;

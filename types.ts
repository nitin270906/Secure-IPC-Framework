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

export const PYTHON_CODE = `# secure_ipc_backend.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import hmac
import hashlib
import secrets
from cryptography.fernet import Fernet
import json
import time
from multiprocessing import Queue, Process, shared_memory
import pickle

app = Flask(__name__)
CORS(app)

class SecurityManager:
    def __init__(self):
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.auth_tokens = {}
        self.permissions = {}
        self.secret_key = secrets.token_bytes(32)
    
    def register_process(self, process_id, permissions=None):
        token = secrets.token_urlsafe(32)
        self.auth_tokens[process_id] = token
        self.permissions[process_id] = permissions or ["read", "write"]
        return token
    
    def authenticate(self, process_id, token):
        return self.auth_tokens.get(process_id) == token
    
    def encrypt_data(self, data):
        serialized = json.dumps(data).encode()
        return self.cipher.encrypt(serialized).decode()
    
    def decrypt_data(self, encrypted_data):
        decrypted = self.cipher.decrypt(encrypted_data.encode())
        return json.loads(decrypted.decode())
    
    def sign_message(self, message):
        return hmac.new(
            self.secret_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()

security = SecurityManager()
message_queues = {}

@app.route('/api/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    process_id = data.get('process_id')
    permissions = data.get('permissions', ['read', 'write'])
    
    token = security.register_process(process_id, permissions)
    
    return jsonify({
        'success': True,
        'token': token,
        'process_id': process_id
    })

@app.route('/api/send', methods=['POST'])
def send_message():
    data = request.json
    process_id = data.get('process_id')
    token = data.get('token')
    message = data.get('message')
    ipc_method = data.get('ipc_method', 'queue')
    encrypt = data.get('encrypt', False)
    
    if not security.authenticate(process_id, token):
        return jsonify({'success': False, 'error': 'Authentication failed'}), 401
    
    # Encrypt if requested
    if encrypt:
        message = security.encrypt_data(message)
    
    # Generate signature
    signature = security.sign_message(str(message))
    
    # Store message in appropriate IPC structure
    channel_id = f"{process_id}_{ipc_method}"
    if channel_id not in message_queues:
        message_queues[channel_id] = []
    
    message_queues[channel_id].append({
        'data': message,
        'signature': signature,
        'timestamp': time.time(),
        'encrypted': encrypt
    })
    
    return jsonify({
        'success': True,
        'signature': signature,
        'method': ipc_method
    })

@app.route('/api/receive', methods=['POST'])
def receive_message():
    data = request.json
    process_id = data.get('process_id')
    token = data.get('token')
    ipc_method = data.get('ipc_method', 'queue')
    
    if not security.authenticate(process_id, token):
        return jsonify({'success': False, 'error': 'Authentication failed'}), 401
    
    channel_id = f"{process_id}_{ipc_method}"
    
    if channel_id not in message_queues or not message_queues[channel_id]:
        return jsonify({'success': False, 'error': 'No messages available'}), 404
    
    message = message_queues[channel_id].pop(0)
    
    # Decrypt if needed
    if message['encrypted']:
        message['data'] = security.decrypt_data(message['data'])
    
    return jsonify({
        'success': True,
        'message': message
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
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
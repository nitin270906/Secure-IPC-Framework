import React, { useState } from 'react';
import { Server } from 'lucide-react';
import ControlPanel from './components/ControlPanel';
import ActivityLogs from './components/ActivityLogs';
import CodeViewer from './components/CodeViewer';
import Documentation from './components/Documentation';
import StatsDashboard from './components/StatsDashboard';
import NetworkVisualizer from './components/NetworkVisualizer';
import PacketInspector from './components/PacketInspector';
import SystemMonitor from './components/SystemMonitor';
import { Log, IpcMethod, ActiveTab, PYTHON_CODE, JAVA_CODE, ChannelData, SystemStats } from './types';

const App = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('demo');
  const [ipcMethod, setIpcMethod] = useState<IpcMethod>('queue');
  const [message, setMessage] = useState('');
  const [encrypt, setEncrypt] = useState(false);
  const [signingEnabled, setSigningEnabled] = useState(true);
  const [logs, setLogs] = useState<Log[]>([]);
  const [processId, setProcessId] = useState('process_alpha_1');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [authToken, setAuthToken] = useState('');
  
  // New State for features
  const [channelData, setChannelData] = useState<ChannelData | null>(null);
  const [stats, setStats] = useState<SystemStats>({
    sent: 0,
    received: 0,
    integrityErrors: 0,
    tamperAttempts: 0
  });

  const addLog = (type: Log['type'], message: string) => {
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
    const ms = now.getMilliseconds().toString().padStart(3, '0');
    const timestamp = `${timeStr}.${ms}`;
    setLogs(prev => [...prev, { type, message, timestamp }]);
  };

  const handleAuthenticate = () => {
    addLog('info', `Initiating handshake for ${processId}...`);
    addLog('debug', 'Protocol: TLS 1.3 handshake initiated.');
    addLog('debug', 'Generating ephemeral keypair for session negotiation.');
    
    setTimeout(() => {
        const token = 'tok_' + Math.random().toString(36).substr(2, 16);
        setAuthToken(token);
        setIsAuthenticated(true);
        addLog('debug', 'Token Exchange: AES-GCM session key established.');
        addLog('success', `Process authenticated. Session Token: ${token.substr(0, 12)}...`);
    }, 600);
  };

  const generateSignature = (data: string) => {
    // Simple deterministic hash simulation for demo purposes
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    // Mix in a secret to make it "HMAC-like"
    return 'hmac_sha256_' + Math.abs(hash).toString(16) + 'x8f2';
  };

  const handleSendMessage = async () => {
    if (!isAuthenticated) {
      addLog('error', 'ACCESS DENIED: Missing valid session token.');
      return;
    }
    if (!message.trim()) {
      addLog('error', 'VALIDATION ERROR: Empty payload rejected.');
      return;
    }
    if (channelData) {
      addLog('warning', 'CHANNEL BUSY: Wait for receiver to clear buffer.');
      return;
    }

    const encryptedData = encrypt ? btoa(message) : message;
    
    addLog('info', `OUTBOUND [${ipcMethod.toUpperCase()}]: Preparing payload...`);
    addLog('debug', `Serialization: Converting payload to JSON stream.`);

    if(encrypt) {
      addLog('info', `ENCRYPTION: AES-256 applied. Ciphertext: ${encryptedData.substring(0, 20)}...`);
      addLog('debug', `Cipher: IV generation and block padding complete.`);
    } else {
      addLog('warning', 'SECURITY WARNING: Transmitting payload in plain text. Interception risk detected.');
    }

    // Generate Signature logic based on signingEnabled
    let signature = 'UNSIGNED';
    if (signingEnabled) {
        signature = generateSignature(encryptedData);
        addLog('debug', 'Signing: Computing HMAC-SHA256 signature for integrity check.');
    } else {
        addLog('warning', 'SECURITY WARNING: HMAC Signing disabled. Integrity not guaranteed.');
    }

    // Simulate network delay before it hits the "Visualizer"
    setTimeout(() => {
      setChannelData({
        id: Math.random().toString(36).substr(2, 8),
        payload: encryptedData,
        signature: signature,
        timestamp: Date.now(),
        encrypted: encrypt,
        signed: signingEnabled,
        method: ipcMethod,
        isTampered: false
      });
      setStats(prev => ({ ...prev, sent: prev.sent + 1 }));
      addLog('success', `TRANSMITTED: ${message.length} bytes sent via ${ipcMethod}.`);
      setMessage('');
    }, 500);
  };

  const handleTamper = () => {
    if (!channelData) return;
    
    addLog('warning', 'NETWORK ALERT: Man-in-the-Middle modification detected!');
    setChannelData(prev => prev ? ({
      ...prev,
      payload: prev.payload + "_CORRUPTED",
      isTampered: true
    }) : null);
    setStats(prev => ({ ...prev, tamperAttempts: prev.tamperAttempts + 1 }));
  };

  const handleReceiveMessage = () => {
    if (!isAuthenticated) {
      addLog('error', 'ACCESS DENIED: Authentication required to poll channels.');
      return;
    }
    
    if (!channelData) {
      addLog('debug', 'Buffer Empty: No messages pending in queue.');
      return;
    }

    addLog('info', `POLLING [${ipcMethod.toUpperCase()}] channel...`);
    addLog('debug', `Buffer Check: Reading pending frames from ${ipcMethod} buffer.`);
    
    setTimeout(() => {
      // 1. Verify Integrity
      let isValid = true;
      
      if (channelData.signed) {
        const recomputedSignature = generateSignature(channelData.payload);
        isValid = recomputedSignature === channelData.signature;
        
        if (!isValid) {
          addLog('error', `CRITICAL: Integrity Check Failed! HMAC mismatch. Discarding packet.`);
          addLog('debug', `Expected: ${recomputedSignature.substr(0,10)}..., Received: ${channelData.signature.substr(0,10)}...`);
          setStats(prev => ({ ...prev, integrityErrors: prev.integrityErrors + 1 }));
          setChannelData(null);
          return;
        } else {
          addLog('success', `VERIFICATION: HMAC signature matched. Message valid.`);
        }
      } else {
        addLog('warning', 'SKIPPED: Integrity check bypassed (Unsigned Message).');
        // If it's unsigned, we accept "corrupted" messages without erroring on signature,
        // but decryption might fail below.
      }

      // 2. Decrypt
      let finalMessage = channelData.payload;
      if (channelData.encrypted) {
        try {
          finalMessage = atob(finalMessage);
          addLog('debug', 'Decryption: AES-256 decryption successful.');
        } catch (e) {
            addLog('error', 'Decryption failed: Ciphertext corrupted or invalid.');
            // If we are here, it means signature check passed (or was skipped) but decryption failed.
            // This happens if we tamper an encrypted unsigned message.
            setChannelData(null);
            return;
        }
      }
      
      addLog('success', `RECEIVED: Payload acquired from buffer.`);
      addLog('info', `DECODED: "${finalMessage}"`);
      setStats(prev => ({ ...prev, received: prev.received + 1 }));
      
      // Clear channel
      setChannelData(null);
    }, 800);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white font-sans selection:bg-purple-500 selection:text-white pb-12">
      {/* Background decoration */}
      <div className="fixed inset-0 z-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-purple-900/20 rounded-full blur-3xl"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-900/10 rounded-full blur-3xl"></div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-6 pt-8">
        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-8 border-b border-slate-800 pb-6 gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <div className="p-3 bg-slate-900 rounded-xl border border-slate-700 shadow-lg shadow-purple-900/20">
                <Server className="w-8 h-8 text-purple-400" />
              </div>
              <h1 className="text-4xl font-extrabold bg-gradient-to-r from-white via-purple-200 to-purple-400 bg-clip-text text-transparent">
                Secure IPC Framework
              </h1>
            </div>
            <p className="text-slate-400 text-lg max-w-2xl">
              Enterprise-grade Inter-Process Communication simulator featuring military-grade encryption, HMAC signing, and access control.
            </p>
          </div>
          
          <div className="flex items-center gap-2 bg-slate-900 p-1.5 rounded-lg border border-slate-800 overflow-x-auto max-w-full">
             {(['demo', 'monitoring', 'python', 'java', 'docs'] as ActiveTab[]).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 rounded-md font-semibold text-sm transition-all duration-200 capitalize whitespace-nowrap ${
                  activeTab === tab
                    ? 'bg-purple-600 text-white shadow-lg'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>

        {/* Content Area */}
        <div className="min-h-[600px] animate-in fade-in slide-in-from-bottom-4 duration-500">
          {activeTab === 'demo' && (
            <div className="space-y-6">
              <StatsDashboard stats={stats} />
              
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-[700px]">
                {/* Left Column: Controls & Visualizer */}
                <div className="lg:col-span-7 flex flex-col gap-6">
                  <div className="flex-1">
                     <ControlPanel 
                      processId={processId}
                      setProcessId={setProcessId}
                      isAuthenticated={isAuthenticated}
                      handleAuthenticate={handleAuthenticate}
                      ipcMethod={ipcMethod}
                      setIpcMethod={setIpcMethod}
                      message={message}
                      setMessage={setMessage}
                      encrypt={encrypt}
                      setEncrypt={setEncrypt}
                      signingEnabled={signingEnabled}
                      setSigningEnabled={setSigningEnabled}
                      handleSendMessage={handleSendMessage}
                      isChannelBusy={!!channelData}
                    />
                  </div>
                  <div className="flex-1">
                    <NetworkVisualizer 
                      channelData={channelData} 
                      ipcMethod={ipcMethod}
                      onTamper={handleTamper}
                      onReceive={handleReceiveMessage}
                      isAuthenticated={isAuthenticated}
                    />
                  </div>
                </div>

                {/* Right Column: Logs & Inspector */}
                <div className="lg:col-span-5 flex flex-col gap-6">
                   <div className="flex-1 min-h-[300px]">
                    <ActivityLogs logs={logs} clearLogs={() => setLogs([])} />
                   </div>
                   <div className="flex-1 min-h-[300px]">
                     <PacketInspector channelData={channelData} />
                   </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'monitoring' && (
            <SystemMonitor channelData={channelData} />
          )}

          {activeTab === 'python' && (
            <CodeViewer 
              code={PYTHON_CODE} 
              language="python" 
              title="Python Backend Implementation (Flask)" 
              colorClass="text-green-300"
            />
          )}

          {activeTab === 'java' && (
            <CodeViewer 
              code={JAVA_CODE} 
              language="java" 
              title="Java Backend Implementation (Spring Boot)" 
              colorClass="text-blue-300"
            />
          )}

          {activeTab === 'docs' && (
            <Documentation />
          )}
        </div>
      </div>
    </div>
  );
};

export default App;
import React from 'react';
import { Terminal, CheckCircle, AlertCircle, Lock, Unlock, Send, ShieldCheck, ShieldAlert, Info, MessageSquare, FileJson, Database } from 'lucide-react';
import { IpcMethod } from '../types';

interface ControlPanelProps {
  processId: string;
  setProcessId: (id: string) => void;
  isAuthenticated: boolean;
  handleAuthenticate: () => void;
  ipcMethod: IpcMethod;
  setIpcMethod: (method: IpcMethod) => void;
  message: string;
  setMessage: (msg: string) => void;
  encrypt: boolean;
  setEncrypt: (encrypt: boolean) => void;
  signingEnabled: boolean;
  setSigningEnabled: (enabled: boolean) => void;
  handleSendMessage: () => void;
  isChannelBusy: boolean;
}

const ControlPanel: React.FC<ControlPanelProps> = ({
  processId,
  setProcessId,
  isAuthenticated,
  handleAuthenticate,
  ipcMethod,
  setIpcMethod,
  message,
  setMessage,
  encrypt,
  setEncrypt,
  signingEnabled,
  setSigningEnabled,
  handleSendMessage,
  isChannelBusy
}) => {
  const quickScenarios = [
    { label: 'Hello World', icon: MessageSquare, value: 'Hello Secure World!' },
    { label: 'JSON Config', icon: FileJson, value: '{\n  "command": "system_check",\n  "target": "kernel",\n  "priority": 1\n}' },
    { label: 'DB Query', icon: Database, value: 'SELECT * FROM users WHERE access_level > 5;' },
  ];

  return (
    <div className="bg-slate-800 rounded-lg p-6 shadow-xl border border-slate-700 flex flex-col h-full relative overflow-hidden">
      {/* Guidance Overlay for Unauthenticated State */}
      {!isAuthenticated && (
         <div className="absolute top-0 right-0 p-2">
            <span className="flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-purple-500"></span>
            </span>
         </div>
      )}

      <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
        <Terminal className="w-6 h-6 text-purple-400" />
        Sender Control
      </h2>

      {/* 1. Authentication Section */}
      <div className={`mb-6 p-4 rounded-lg transition-all border ${
        !isAuthenticated 
          ? 'bg-purple-900/10 border-purple-500/50 shadow-inner' 
          : 'bg-slate-900 border-transparent'
      }`}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
             <label className="font-semibold text-sm uppercase tracking-wider text-slate-400">1. Identity</label>
             {!isAuthenticated && <span className="text-xs text-purple-400 animate-pulse font-medium">← Start Here</span>}
          </div>
          {isAuthenticated ? (
            <div className="flex items-center gap-2 text-green-400">
              <span className="text-xs font-bold">VERIFIED</span>
              <CheckCircle className="w-5 h-5" />
            </div>
          ) : (
            <div className="flex items-center gap-2 text-yellow-400">
              <span className="text-xs font-bold">UNVERIFIED</span>
              <AlertCircle className="w-5 h-5" />
            </div>
          )}
        </div>
        
        <div className="flex gap-2">
          <input
            type="text"
            value={processId}
            onChange={(e) => setProcessId(e.target.value)}
            disabled={isAuthenticated}
            className="flex-1 px-4 py-2 bg-slate-800 border border-slate-600 rounded-lg disabled:opacity-50 text-white text-sm focus:outline-none focus:border-purple-500 transition-colors"
            placeholder="Process ID"
          />
          <button
            onClick={handleAuthenticate}
            disabled={isAuthenticated}
            className={`px-4 py-2 rounded-lg font-semibold transition-all flex items-center gap-2 whitespace-nowrap ${
              isAuthenticated 
                ? 'bg-green-600/20 text-green-400 cursor-not-allowed border border-green-600/50' 
                : 'bg-purple-600 hover:bg-purple-700 text-white shadow-lg hover:shadow-purple-500/25 animate-pulse-subtle'
            }`}
          >
            {isAuthenticated ? <Lock className="w-4 h-4" /> : <Unlock className="w-4 h-4" />}
            {isAuthenticated ? 'Auth OK' : 'Connect'}
          </button>
        </div>
      </div>

      <div className={`flex-1 flex flex-col gap-4 transition-opacity duration-300 ${!isAuthenticated ? 'opacity-50 pointer-events-none grayscale-[0.5]' : 'opacity-100'}`}>
        {/* IPC Method Selection */}
        <div className="group">
          <div className="flex items-center justify-between mb-2">
            <label className="block font-semibold text-sm uppercase tracking-wider text-slate-400">2. Channel Type</label>
            <div className="relative group/tooltip">
              <Info className="w-4 h-4 text-slate-500 cursor-help" />
              <div className="absolute right-0 bottom-full mb-2 w-64 p-2 bg-slate-900 border border-slate-600 rounded text-xs text-slate-300 hidden group-hover/tooltip:block z-10 shadow-xl">
                Choose the underlying OS mechanism for data transfer. Queues are FIFO, Pipes are streams, and Shared Memory is fastest but complex.
              </div>
            </div>
          </div>
          <select
            value={ipcMethod}
            onChange={(e) => setIpcMethod(e.target.value as IpcMethod)}
            className="w-full px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-purple-500 transition-colors cursor-pointer hover:bg-slate-800"
          >
            <option value="queue">Message Queue (System V IPC)</option>
            <option value="pipe">Named Pipe (FIFO)</option>
            <option value="shared_memory">Shared Memory Segment</option>
          </select>
        </div>

        {/* Message Input & Scenarios */}
        <div className="flex-1 min-h-[140px] flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <label className="block font-semibold text-sm uppercase tracking-wider text-slate-400">3. Payload</label>
            <div className="flex gap-1">
               {quickScenarios.map((s, i) => (
                 <button
                   key={i}
                   onClick={() => setMessage(s.value)}
                   className="p-1.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors"
                   title={`Quick fill: ${s.label}`}
                 >
                   <s.icon className="w-3 h-3" />
                 </button>
               ))}
            </div>
          </div>
          <textarea
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Enter data to transmit..."
            className="w-full flex-1 px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg resize-none font-mono text-sm text-slate-300 focus:outline-none focus:border-purple-500 transition-colors placeholder-slate-600"
          />
        </div>

        {/* Security Configuration */}
        <div className="bg-slate-900 rounded-lg border border-slate-700/50 p-3">
          <div className="flex items-center justify-between mb-2">
            <label className="block font-semibold text-xs uppercase tracking-wider text-slate-400">Security Layers</label>
            <span className="text-[10px] text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full border border-slate-700">AES-256-GCM + HMAC</span>
          </div>
          <div className="grid grid-cols-2 gap-3">
             {/* Encryption Toggle */}
            <div 
              onClick={() => setEncrypt(!encrypt)}
              className={`p-2 rounded-lg border cursor-pointer select-none transition-all flex items-center justify-between ${encrypt ? 'bg-green-900/20 border-green-500/30' : 'bg-slate-800 border-slate-700 hover:border-slate-600'}`}
            >
              <div className="flex items-center gap-2">
                 {encrypt ? <Lock className="w-3 h-3 text-green-400" /> : <Unlock className="w-3 h-3 text-slate-500" />}
                 <span className={`text-xs font-medium ${encrypt ? 'text-green-400' : 'text-slate-400'}`}>Encryption</span>
              </div>
              <div className={`w-2 h-2 rounded-full ${encrypt ? 'bg-green-500' : 'bg-slate-600'}`}></div>
            </div>

            {/* Signing Toggle */}
             <div 
               onClick={() => setSigningEnabled(!signingEnabled)}
               className={`p-2 rounded-lg border cursor-pointer select-none transition-all flex items-center justify-between ${signingEnabled ? 'bg-blue-900/20 border-blue-500/30' : 'bg-slate-800 border-slate-700 hover:border-slate-600'}`}
             >
               <div className="flex items-center gap-2">
                  {signingEnabled ? <ShieldCheck className="w-3 h-3 text-blue-400" /> : <ShieldAlert className="w-3 h-3 text-slate-500" />}
                  <span className={`text-xs font-medium ${signingEnabled ? 'text-blue-400' : 'text-slate-400'}`}>HMAC Sign</span>
               </div>
               <div className={`w-2 h-2 rounded-full ${signingEnabled ? 'bg-blue-500' : 'bg-slate-600'}`}></div>
            </div>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="mt-4 pt-4 border-t border-slate-700">
        <button
          onClick={handleSendMessage}
          disabled={!isAuthenticated || !message.trim() || isChannelBusy}
          className={`w-full px-4 py-3 rounded-lg font-bold text-white transition-all flex items-center justify-center gap-2 ${
             !isAuthenticated || !message.trim() || isChannelBusy
              ? 'bg-slate-700 text-slate-400 cursor-not-allowed opacity-75'
              : 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 shadow-lg hover:shadow-purple-500/25 active:scale-95'
          }`}
        >
          {isChannelBusy ? (
             <>Channel Busy (Wait for Receiver)</>
          ) : (
             <>
               <Send className="w-5 h-5" />
               Transmit Packet
             </>
          )}
        </button>
      </div>
    </div>
  );
};

export default ControlPanel;
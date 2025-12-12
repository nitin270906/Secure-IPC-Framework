import React from 'react';
import { Terminal, CheckCircle, AlertCircle, Lock, Unlock, Send, ShieldCheck, Info, MessageSquare, FileJson, Database, Shield, Eye, Edit3, Key, ChevronDown, Stethoscope } from 'lucide-react';
import { IpcMethod } from '../types';

interface ControlPanelProps {
  processId: string;
  setProcessId: (id: string) => void;
  permissions: string;
  setPermissions: (p: string) => void;
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
  runDiagnostics?: () => void;
  isDiagnosing?: boolean;
}

const ControlPanel: React.FC<ControlPanelProps> = ({
  processId,
  setProcessId,
  permissions,
  setPermissions,
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
  isChannelBusy,
  runDiagnostics,
  isDiagnosing = false
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

      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <Terminal className="w-6 h-6 text-purple-400" />
          Sender Control
        </h2>
        
        {runDiagnostics && (
            <button 
                onClick={runDiagnostics}
                disabled={isDiagnosing}
                className="flex items-center gap-1.5 px-3 py-1 bg-slate-700 hover:bg-slate-600 rounded-md text-xs font-mono text-slate-300 border border-slate-600 transition-colors disabled:opacity-50"
            >
                <Stethoscope className={`w-3.5 h-3.5 ${isDiagnosing ? 'animate-pulse text-yellow-400' : 'text-slate-400'}`} />
                {isDiagnosing ? 'Running Tests...' : 'Run Diagnostics'}
            </button>
        )}
      </div>

      {/* 1. Identity & Access Section */}
      <div className={`mb-4 p-4 rounded-lg transition-all border ${
        !isAuthenticated 
          ? 'bg-purple-900/10 border-purple-500/50 shadow-inner' 
          : 'bg-slate-900 border-transparent'
      }`}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
             <label className="font-semibold text-sm uppercase tracking-wider text-slate-400">1. Identity & Permissions</label>
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
        
        <div className="space-y-4 mb-4">
          <div>
            <label className="block text-[10px] uppercase text-slate-500 font-bold mb-1.5">Process Identifier</label>
            <input
              type="text"
              value={processId}
              onChange={(e) => setProcessId(e.target.value)}
              disabled={isAuthenticated}
              className="w-full px-4 py-2 bg-slate-800 border border-slate-600 rounded-lg disabled:opacity-50 text-white text-sm focus:outline-none focus:border-purple-500 transition-colors placeholder-slate-600 font-mono"
              placeholder="e.g. process_alpha_1"
            />
          </div>
          
          <div>
            <label className="block text-[10px] uppercase text-slate-500 font-bold mb-1.5">Access Control List (ACL)</label>
            <div className="relative">
              <select
                value={permissions}
                onChange={(e) => setPermissions(e.target.value)}
                disabled={isAuthenticated}
                className="w-full appearance-none px-4 py-2.5 bg-slate-800 border border-slate-600 rounded-lg disabled:opacity-50 text-white text-sm focus:outline-none focus:border-purple-500 transition-colors cursor-pointer hover:bg-slate-750"
              >
                <option value="read">Read Only (Observer)</option>
                <option value="write">Read & Write (Contributor)</option>
                <option value="admin">Administrator (Root)</option>
              </select>
              <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400">
                <ChevronDown className="w-4 h-4" />
              </div>
            </div>
            
            {/* Visual Feedback for Permissions */}
            <div className="mt-2 flex items-center gap-2 text-xs">
               <span className="text-slate-500">Effective Role:</span>
               {permissions === 'admin' && <span className="text-red-400 font-bold flex items-center gap-1"><Key className="w-3 h-3"/> Full System Root</span>}
               {permissions === 'write' && <span className="text-purple-400 font-bold flex items-center gap-1"><Edit3 className="w-3 h-3"/> Read/Write Access</span>}
               {permissions === 'read' && <span className="text-blue-400 font-bold flex items-center gap-1"><Eye className="w-3 h-3"/> Read Only Access</span>}
            </div>
          </div>
        </div>

        <button
          onClick={handleAuthenticate}
          disabled={isAuthenticated}
          className={`w-full px-4 py-2 rounded-lg font-semibold transition-all flex items-center justify-center gap-2 whitespace-nowrap ${
            isAuthenticated 
              ? 'bg-green-600/20 text-green-400 cursor-not-allowed border border-green-600/50' 
              : 'bg-purple-600 hover:bg-purple-700 text-white shadow-lg hover:shadow-purple-500/25 animate-pulse-subtle'
          }`}
        >
          {isAuthenticated ? <Lock className="w-4 h-4" /> : <Unlock className="w-4 h-4" />}
          {isAuthenticated ? 'Session Authenticated' : 'Authenticate Process'}
        </button>
      </div>

      <div className={`flex-1 flex flex-col gap-4 transition-opacity duration-300 ${!isAuthenticated ? 'opacity-50 pointer-events-none grayscale-[0.5]' : 'opacity-100'}`}>
        
        {/* 2. Channel Selection */}
        <div className="group">
          <div className="flex items-center justify-between mb-2">
            <label className="block font-semibold text-xs uppercase tracking-wider text-slate-400">2. Transport Layer</label>
            <div className="relative group/tooltip">
              <Info className="w-3 h-3 text-slate-500 cursor-help" />
              <div className="absolute right-0 bottom-full mb-2 w-64 p-2 bg-slate-900 border border-slate-600 rounded text-xs text-slate-300 hidden group-hover/tooltip:block z-10 shadow-xl">
                Select the OS primitive for data transfer. Queues are message-based, Pipes are streams, Shared Memory is direct access.
              </div>
            </div>
          </div>
          <div className="relative">
            <select
              value={ipcMethod}
              onChange={(e) => setIpcMethod(e.target.value as IpcMethod)}
              className="w-full appearance-none px-4 py-2.5 bg-slate-900 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-purple-500 transition-colors cursor-pointer hover:bg-slate-800"
            >
              <option value="queue">Message Queue (System V IPC)</option>
              <option value="pipe">Named Pipe (FIFO)</option>
              <option value="shared_memory">Shared Memory Segment</option>
            </select>
            <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400">
                <ChevronDown className="w-4 h-4" />
            </div>
          </div>
        </div>

        {/* 3. Security Protocols (Dedicated Section) */}
        <div className="bg-slate-900/50 rounded-xl border border-slate-700 p-4">
             <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-700/50">
                <Shield className="w-4 h-4 text-purple-400" />
                <label className="font-semibold text-xs uppercase tracking-wider text-slate-300">3. Security Protocols</label>
             </div>
             
             <div className="grid grid-cols-2 gap-4">
                {/* Encryption Toggle */}
                <div 
                    onClick={() => setEncrypt(!encrypt)}
                    className={`relative p-3 rounded-lg border cursor-pointer transition-all duration-200 group ${
                        encrypt 
                        ? 'bg-green-900/20 border-green-500/50 shadow-[0_0_15px_rgba(34,197,94,0.1)]' 
                        : 'bg-slate-800 border-slate-600 hover:border-slate-500'
                    }`}
                >
                    <div className="flex items-start justify-between mb-2">
                         <div className={`p-1.5 rounded ${encrypt ? 'bg-green-500/20 text-green-400' : 'bg-slate-700 text-slate-400'}`}>
                            <Lock className="w-4 h-4" />
                         </div>
                         <div className={`w-8 h-4 rounded-full p-0.5 transition-colors ${encrypt ? 'bg-green-500' : 'bg-slate-600'}`}>
                            <div className={`w-3 h-3 rounded-full bg-white shadow-sm transition-transform ${encrypt ? 'translate-x-4' : 'translate-x-0'}`} />
                         </div>
                    </div>
                    <div className="space-y-0.5">
                        <div className={`text-sm font-bold ${encrypt ? 'text-green-300' : 'text-slate-300'}`}>AES-256</div>
                        <div className="text-[10px] text-slate-500 leading-tight">GCM Block Cipher</div>
                    </div>
                </div>

                {/* Signing Toggle */}
                <div 
                    onClick={() => setSigningEnabled(!signingEnabled)}
                    className={`relative p-3 rounded-lg border cursor-pointer transition-all duration-200 group ${
                        signingEnabled 
                        ? 'bg-blue-900/20 border-blue-500/50 shadow-[0_0_15px_rgba(59,130,246,0.1)]' 
                        : 'bg-slate-800 border-slate-600 hover:border-slate-500'
                    }`}
                >
                     <div className="flex items-start justify-between mb-2">
                         <div className={`p-1.5 rounded ${signingEnabled ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-700 text-slate-400'}`}>
                            <ShieldCheck className="w-4 h-4" />
                         </div>
                         <div className={`w-8 h-4 rounded-full p-0.5 transition-colors ${signingEnabled ? 'bg-blue-500' : 'bg-slate-600'}`}>
                            <div className={`w-3 h-3 rounded-full bg-white shadow-sm transition-transform ${signingEnabled ? 'translate-x-4' : 'translate-x-0'}`} />
                         </div>
                    </div>
                    <div className="space-y-0.5">
                        <div className={`text-sm font-bold ${signingEnabled ? 'text-blue-300' : 'text-slate-300'}`}>HMAC-SHA256</div>
                        <div className="text-[10px] text-slate-500 leading-tight">Digital Signature</div>
                    </div>
                </div>
             </div>
        </div>

        {/* 4. Message Input */}
        <div className="flex-1 min-h-[140px] flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <label className="block font-semibold text-xs uppercase tracking-wider text-slate-400">4. Payload</label>
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
            className="w-full flex-1 px-4 py-3 bg-slate-900 border border-slate-600 rounded-lg resize-none font-mono text-sm text-slate-300 focus:outline-none focus:border-purple-500 transition-colors placeholder-slate-600 shadow-inner"
          />
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
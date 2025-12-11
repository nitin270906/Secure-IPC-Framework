import React from 'react';
import { Network, Database, ArrowDown, ShieldAlert, Download, Cpu, ArrowRight } from 'lucide-react';
import { ChannelData, IpcMethod } from '../types';

interface NetworkVisualizerProps {
  channelData: ChannelData | null;
  ipcMethod: IpcMethod;
  onTamper: () => void;
  onReceive: () => void;
  isAuthenticated: boolean;
}

const NetworkVisualizer: React.FC<NetworkVisualizerProps> = ({
  channelData,
  ipcMethod,
  onTamper,
  onReceive,
  isAuthenticated
}) => {
  const getMethodLabel = (m: IpcMethod) => {
    switch(m) {
      case 'queue': return 'Message Queue';
      case 'pipe': return 'Named Pipe';
      case 'shared_memory': return 'Shared Memory';
      default: return m;
    }
  };

  return (
    <div className="bg-slate-800 rounded-lg p-6 shadow-xl border border-slate-700 flex flex-col gap-4">
      <h2 className="text-xl font-bold flex items-center gap-2">
        <Network className="w-6 h-6 text-purple-400" />
        Channel Visualizer
      </h2>

      <div className="bg-slate-900/50 rounded-xl p-6 border-2 border-dashed border-slate-700 relative min-h-[220px] flex flex-col items-center justify-center transition-all overflow-hidden group">
        
        {/* Background Grid Decoration */}
        <div className="absolute inset-0 opacity-[0.03]" 
             style={{ backgroundImage: 'radial-gradient(#fff 1px, transparent 1px)', backgroundSize: '20px 20px' }}>
        </div>

        {/* Connection Status Label */}
        <div className="absolute top-4 right-4 flex items-center gap-2 z-10">
          <div className={`w-2 h-2 rounded-full ${isAuthenticated ? 'bg-green-500 animate-pulse' : 'bg-slate-600'}`}></div>
          <span className="text-xs font-mono text-slate-500 uppercase">
            {isAuthenticated ? 'LINK ACTIVE' : 'LINK OFFLINE'}
          </span>
        </div>

        {/* Channel Type */}
        <div className="absolute top-4 left-4 text-xs font-mono text-purple-400 uppercase tracking-wider z-10">
          PROTOCOL: {getMethodLabel(ipcMethod)}
        </div>

        {channelData ? (
          <div className="w-full max-w-sm bg-slate-800 rounded-lg p-4 border border-purple-500/50 shadow-lg shadow-purple-900/20 animate-in zoom-in duration-300 relative z-10">
            {/* Packet Header */}
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-slate-700">
              <div className="flex items-center gap-2">
                <div className="p-1.5 bg-purple-900/50 rounded text-purple-300">
                  <Database className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-sm font-bold text-white">Encrypted Frame</div>
                  <div className="text-[10px] text-slate-400 font-mono uppercase">Size: {channelData.payload.length}B</div>
                </div>
              </div>
              <div className="px-2 py-0.5 bg-slate-900 rounded text-[10px] text-slate-500 font-mono">
                PENDING
              </div>
            </div>

            {/* Warning if Tampered */}
            {channelData.isTampered && (
              <div className="mb-3 px-3 py-1.5 bg-red-900/20 border border-red-500/30 rounded flex items-center gap-2 text-red-400 text-xs font-bold animate-pulse">
                <ShieldAlert className="w-3 h-3" />
                INTEGRITY COMPROMISED
              </div>
            )}

            {/* Actions */}
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={onTamper}
                disabled={channelData.isTampered}
                className="flex items-center justify-center gap-2 px-3 py-2.5 bg-slate-700 hover:bg-red-900/30 hover:text-red-400 hover:border-red-500/50 border border-transparent rounded transition-all text-xs font-bold disabled:opacity-50 disabled:cursor-not-allowed group/btn"
              >
                <ShieldAlert className="w-3.5 h-3.5 group-hover/btn:animate-bounce" />
                Simulate Attack
              </button>
              <button
                onClick={onReceive}
                className="flex items-center justify-center gap-2 px-3 py-2.5 bg-purple-600 hover:bg-purple-500 text-white rounded transition-all text-xs font-bold shadow-lg shadow-purple-900/30 animate-pulse"
              >
                <Download className="w-3.5 h-3.5" />
                Process (Receive)
              </button>
            </div>
          </div>
        ) : (
          <div className="text-center text-slate-600 relative z-10">
            {isAuthenticated ? (
               <div className="flex flex-col items-center gap-2">
                 <div className="w-16 h-16 rounded-full bg-slate-800/50 flex items-center justify-center border-2 border-dashed border-slate-700">
                    <ArrowDown className="w-6 h-6 animate-bounce opacity-50" />
                 </div>
                 <p className="text-sm font-medium text-slate-400">Channel Idle</p>
                 <p className="text-xs opacity-50">Compose and Transmit a message from the <br/>Control Panel to see it here.</p>
               </div>
            ) : (
               <div className="flex flex-col items-center gap-2">
                 <Cpu className="w-12 h-12 opacity-20" />
                 <p className="text-sm font-medium">System Offline</p>
                 <p className="text-xs opacity-50">Authenticate Process to initialize link.</p>
               </div>
            )}
          </div>
        )}
      </div>

      {channelData && (
        <div className="flex items-center justify-center gap-2 text-xs text-purple-400 font-medium animate-in fade-in slide-in-from-top-2">
           <InfoIcon />
           <span>Packet holding in {getMethodLabel(ipcMethod)}. Receiver ready.</span>
        </div>
      )}
    </div>
  );
};

const InfoIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
  </svg>
)

export default NetworkVisualizer;
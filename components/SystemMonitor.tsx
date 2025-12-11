import React from 'react';
import { Layers, Activity, HardDrive, Cpu, Lock, ArrowRight, Server, Box } from 'lucide-react';
import { ChannelData, IpcMethod } from '../types';

interface SystemMonitorProps {
  channelData: ChannelData | null;
}

const SystemMonitor: React.FC<SystemMonitorProps> = ({ channelData }) => {
  const getChannelStatus = (method: IpcMethod) => {
    const isActive = channelData?.method === method;
    
    if (isActive) {
      if (method === 'shared_memory') return { status: 'LOCKED', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' };
      return { status: 'DATA PENDING', color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30' };
    }
    return { status: 'IDLE', color: 'text-slate-500', bg: 'bg-slate-800/50 border-slate-700' };
  };

  const getLoad = (method: IpcMethod) => {
    return channelData?.method === method ? Math.floor(Math.random() * 30) + 40 : 0;
  };

  const renderChannelCard = (method: IpcMethod, title: string, Icon: React.ElementType, details: string) => {
    const { status, color, bg } = getChannelStatus(method);
    const load = getLoad(method);
    const isActive = channelData?.method === method;

    return (
      <div className={`rounded-xl p-6 border transition-all duration-500 ${bg} relative overflow-hidden`}>
        {isActive && (
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-purple-500 to-transparent animate-pulse" />
        )}
        
        <div className="flex items-start justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className={`p-3 rounded-lg ${isActive ? 'bg-purple-600 shadow-lg shadow-purple-900/40' : 'bg-slate-700'}`}>
              <Icon className={`w-6 h-6 ${isActive ? 'text-white' : 'text-slate-400'}`} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">{title}</h3>
              <div className="text-xs text-slate-400 font-mono">{details}</div>
            </div>
          </div>
          <div className={`px-3 py-1 rounded text-xs font-bold font-mono border ${
            status === 'LOCKED' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
            status === 'DATA PENDING' ? 'bg-green-500/20 text-green-400 border-green-500/30' :
            'bg-slate-700 text-slate-400 border-slate-600'
          }`}>
            {status}
          </div>
        </div>

        <div className="space-y-4">
          <div>
            <div className="flex justify-between text-xs mb-2">
              <span className="text-slate-400">Buffer Usage</span>
              <span className={color}>{load}%</span>
            </div>
            <div className="h-2 bg-slate-900 rounded-full overflow-hidden">
              <div 
                className={`h-full transition-all duration-500 ${
                  status === 'LOCKED' ? 'bg-red-500' : 'bg-purple-500'
                }`} 
                style={{ width: `${load}%` }}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 pt-4 border-t border-slate-700/50">
            <div>
              <div className="text-xs text-slate-500 mb-1">Process Lock</div>
              <div className="flex items-center gap-1.5 text-sm font-medium text-slate-300">
                {status === 'LOCKED' ? (
                  <>
                    <Lock className="w-3 h-3 text-red-400" />
                    <span>Exclusive</span>
                  </>
                ) : (
                  <>
                    <Activity className="w-3 h-3 text-slate-500" />
                    <span>None</span>
                  </>
                )}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Throughput</div>
              <div className="text-sm font-medium text-slate-300">
                {isActive ? '256 MB/s' : '0 B/s'}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="bg-slate-800 rounded-lg p-8 shadow-xl border border-slate-700">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-bold flex items-center gap-2 mb-2">
            <Activity className="w-6 h-6 text-purple-400" />
            Active Channel Monitoring
          </h2>
          <p className="text-slate-400">Real-time status of inter-process communication subsystems.</p>
        </div>
        <div className="flex gap-2">
           <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 rounded border border-slate-700">
             <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
             <span className="text-xs font-mono text-slate-400">SYSTEM ONLINE</span>
           </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {renderChannelCard('queue', 'Message Queue', Layers, 'System V IPC Queue')}
        {renderChannelCard('pipe', 'Named Pipe', Server, '/tmp/secure_fifo')}
        {renderChannelCard('shared_memory', 'Shared Memory', HardDrive, '/dev/shm/secure_seg')}
      </div>

      <div className="mt-8 bg-slate-900/50 rounded-lg p-6 border border-slate-700">
         <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Cpu className="w-4 h-4" />
            Kernel Metrics
         </h3>
         <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            <div>
                <div className="text-xs text-slate-500 mb-1">Context Switches</div>
                <div className="text-xl font-mono text-white">1,402 /sec</div>
            </div>
             <div>
                <div className="text-xs text-slate-500 mb-1">Interrupts</div>
                <div className="text-xl font-mono text-white">892 /sec</div>
            </div>
             <div>
                <div className="text-xs text-slate-500 mb-1">Page Faults</div>
                <div className="text-xl font-mono text-white">0</div>
            </div>
             <div>
                <div className="text-xs text-slate-500 mb-1">System Load</div>
                <div className="text-xl font-mono text-green-400">0.12</div>
            </div>
         </div>
      </div>
    </div>
  );
};

export default SystemMonitor;
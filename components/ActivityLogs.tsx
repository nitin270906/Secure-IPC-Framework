import React, { useRef, useEffect, useState } from 'react';
import { Activity, Trash2, Filter } from 'lucide-react';
import { Log } from '../types';

interface ActivityLogsProps {
  logs: Log[];
  clearLogs: () => void;
}

const ActivityLogs: React.FC<ActivityLogsProps> = ({ logs, clearLogs }) => {
  const [filter, setFilter] = useState<'all' | Log['type']>('all');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, filter]);

  const filteredLogs = logs.filter(log => filter === 'all' || log.type === filter);

  const getLogStyle = (type: Log['type']) => {
    switch(type) {
      case 'success': return 'bg-green-900/10 border-green-500/50 text-green-400';
      case 'error': return 'bg-red-900/10 border-red-500/50 text-red-400';
      case 'info': return 'bg-blue-900/10 border-blue-500/50 text-blue-400';
      case 'warning': return 'bg-orange-900/10 border-orange-500/50 text-orange-400';
      case 'debug': return 'bg-gray-800/40 border-gray-700/50 text-gray-400 text-xs font-mono tracking-tight';
      default: return 'text-slate-300';
    }
  };

  const filters: { id: 'all' | Log['type'], label: string, color: string }[] = [
    { id: 'all', label: 'All', color: 'bg-slate-700' },
    { id: 'success', label: 'Success', color: 'bg-green-600' },
    { id: 'error', label: 'Error', color: 'bg-red-600' },
    { id: 'info', label: 'Info', color: 'bg-blue-600' },
    { id: 'warning', label: 'Warning', color: 'bg-orange-600' },
    { id: 'debug', label: 'Debug', color: 'bg-gray-600' },
  ];

  return (
    <div className="bg-slate-800 rounded-lg p-6 shadow-xl border border-slate-700 h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold flex items-center gap-2">
          <Activity className="w-6 h-6 text-purple-400" />
          System Telemetry
        </h2>
        <button
          onClick={clearLogs}
          className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-700/50 rounded-lg transition-colors"
          title="Clear Logs"
        >
          <Trash2 className="w-5 h-5" />
        </button>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap gap-2 mb-3">
        <div className="flex items-center mr-2 text-slate-400 text-sm">
          <Filter className="w-4 h-4 mr-1" />
          <span>Filters:</span>
        </div>
        {filters.map(f => (
          <button
            key={f.id}
            onClick={() => setFilter(f.id)}
            className={`px-3 py-1 rounded-full text-xs font-semibold transition-all ${
              filter === f.id 
                ? `${f.color} text-white shadow-lg scale-105` 
                : 'bg-slate-700/50 text-slate-400 hover:bg-slate-700 hover:text-white'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>
      
      <div 
        ref={scrollRef}
        className="flex-1 bg-slate-900/80 rounded-lg p-4 overflow-y-auto font-mono text-sm border border-slate-700/50 shadow-inner"
      >
        {logs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-600 gap-2">
            <Activity className="w-12 h-12 opacity-20" />
            <p>Awaiting process activity...</p>
            <p className="text-xs opacity-60">Authenticate and transmit data to begin logging.</p>
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-600 gap-2">
            <p className="text-sm opacity-60">No logs found matching filter "{filter}".</p>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {filteredLogs.map((log, idx) => (
              <div 
                key={idx} 
                className={`p-2 rounded border-l-2 animate-in fade-in slide-in-from-left-2 duration-300 ${getLogStyle(log.type)}`}
              >
                <div className="flex gap-3 text-xs opacity-50 mb-1">
                  <span className="font-semibold uppercase tracking-wider">{log.type}</span>
                  <span>{log.timestamp}</span>
                </div>
                <div className="break-words font-medium">
                  {log.message}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
      
      <div className="mt-4 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500 justify-end border-t border-slate-700/50 pt-2">
         {/* Simplified legend since filters serve as legend too */}
        <span className="text-slate-600 italic">Total Records: {logs.length}</span>
      </div>
    </div>
  );
};

export default ActivityLogs;
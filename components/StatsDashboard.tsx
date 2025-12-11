import React from 'react';
import { Send, Download, ShieldAlert, Activity } from 'lucide-react';
import { SystemStats } from '../types';

interface StatsDashboardProps {
  stats: SystemStats;
}

const StatsDashboard: React.FC<StatsDashboardProps> = ({ stats }) => {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div className="bg-slate-800 p-4 rounded-lg border border-slate-700 shadow-lg">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-purple-900/30 rounded-lg text-purple-400">
            <Send className="w-5 h-5" />
          </div>
          <span className="text-slate-400 text-sm font-semibold">Messages Sent</span>
        </div>
        <div className="text-2xl font-bold text-white">{stats.sent}</div>
      </div>

      <div className="bg-slate-800 p-4 rounded-lg border border-slate-700 shadow-lg">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-blue-900/30 rounded-lg text-blue-400">
            <Download className="w-5 h-5" />
          </div>
          <span className="text-slate-400 text-sm font-semibold">Received</span>
        </div>
        <div className="text-2xl font-bold text-white">{stats.received}</div>
      </div>

      <div className="bg-slate-800 p-4 rounded-lg border border-slate-700 shadow-lg">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-red-900/30 rounded-lg text-red-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <span className="text-slate-400 text-sm font-semibold">Integrity Errors</span>
        </div>
        <div className="text-2xl font-bold text-white">{stats.integrityErrors}</div>
      </div>

      <div className="bg-slate-800 p-4 rounded-lg border border-slate-700 shadow-lg">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 bg-orange-900/30 rounded-lg text-orange-400">
            <Activity className="w-5 h-5" />
          </div>
          <span className="text-slate-400 text-sm font-semibold">Tamper Attempts</span>
        </div>
        <div className="text-2xl font-bold text-white">{stats.tamperAttempts}</div>
      </div>
    </div>
  );
};

export default StatsDashboard;
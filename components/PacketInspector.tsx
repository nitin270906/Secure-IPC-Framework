import React from 'react';
import { Search, Hash, Lock, Clock, ShieldAlert } from 'lucide-react';
import { ChannelData } from '../types';

interface PacketInspectorProps {
  channelData: ChannelData | null;
}

const PacketInspector: React.FC<PacketInspectorProps> = ({ channelData }) => {
  if (!channelData) {
    return (
      <div className="bg-slate-800 rounded-lg p-6 shadow-xl border border-slate-700 h-[300px] flex flex-col items-center justify-center text-slate-600">
        <Search className="w-12 h-12 mb-3 opacity-20" />
        <h3 className="font-bold text-lg mb-1">Packet Inspector</h3>
        <p className="text-sm opacity-60">No active packet in transit</p>
      </div>
    );
  }

  return (
    <div className="bg-slate-800 rounded-lg p-6 shadow-xl border border-slate-700 h-full">
      <div className="flex items-center justify-between mb-4 border-b border-slate-700 pb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <Search className="w-5 h-5 text-purple-400" />
          Packet Inspector
        </h2>
        <span className="px-2 py-1 bg-slate-900 rounded text-xs font-mono text-slate-400">
          ID: {channelData.id}
        </span>
      </div>

      <div className="space-y-4 font-mono text-xs">
        <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
          <div className="flex items-center gap-2 text-slate-400 mb-2 uppercase tracking-wider font-bold">
            <Lock className="w-3 h-3" />
            Payload Content
          </div>
          <div className="break-all text-slate-300 bg-slate-950 p-2 rounded">
            {channelData.payload}
          </div>
          {channelData.encrypted && (
            <div className="mt-2 text-green-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full"></span>
              Encrypted (AES-256)
            </div>
          )}
        </div>

        <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
          <div className="flex items-center gap-2 text-slate-400 mb-2 uppercase tracking-wider font-bold">
            <Hash className="w-3 h-3" />
            HMAC Signature
          </div>
          {channelData.signed ? (
            <div className="break-all text-yellow-400 bg-slate-950 p-2 rounded">
              {channelData.signature}
            </div>
          ) : (
            <div className="flex items-center gap-2 p-2 bg-red-900/10 border border-red-900/30 rounded text-red-400">
              <ShieldAlert className="w-4 h-4" />
              <span>UNSIGNED PACKET</span>
            </div>
          )}
        </div>

        <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
          <div className="flex items-center gap-2 text-slate-400 mb-2 uppercase tracking-wider font-bold">
            <Clock className="w-3 h-3" />
            Metadata
          </div>
          <div className="grid grid-cols-2 gap-2 text-slate-300">
            <div>Timestamp: {channelData.timestamp}</div>
            <div>Method: {channelData.method}</div>
            <div>Integrity: {channelData.isTampered ? 'FAIL' : 'PASS'}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PacketInspector;
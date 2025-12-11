import React from 'react';
import { Shield, Key, FileSignature, Users, ArrowRight } from 'lucide-react';

const Documentation: React.FC = () => {
  return (
    <div className="bg-slate-800 rounded-lg p-8 shadow-xl border border-slate-700">
      <h2 className="text-3xl font-bold mb-8 bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">Framework Architecture & Security Specification</h2>
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        <div className="col-span-1 space-y-8">
          <div>
            <h3 className="text-xl font-bold text-purple-400 mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Core Architecture
            </h3>
            <p className="text-slate-300 mb-4 leading-relaxed">The Secure IPC Framework implements a 3-tier isolated architecture designed for high-integrity environments.</p>
            <ul className="space-y-3">
              {[
                { label: 'Frontend Control', desc: 'React-based telemetry dashboard' },
                { label: 'Backend Controller', desc: 'Flask/Spring Boot REST API Gateway' },
                { label: 'IPC Layer', desc: 'System-level queues, pipes, and shared memory' }
              ].map((item, i) => (
                <li key={i} className="flex items-start gap-3 bg-slate-900/50 p-3 rounded-lg border border-slate-700/50">
                  <div className="mt-1 w-1.5 h-1.5 rounded-full bg-purple-500 shrink-0" />
                  <div>
                    <strong className="block text-white text-sm">{item.label}</strong>
                    <span className="text-slate-400 text-xs">{item.desc}</span>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="col-span-1 lg:col-span-2">
          <h3 className="text-xl font-bold text-purple-400 mb-4 flex items-center gap-2">
            <Key className="w-5 h-5" />
            Security Implementation
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-900 p-5 rounded-xl border border-slate-700 hover:border-purple-500/30 transition-colors group">
              <div className="mb-3 w-10 h-10 rounded-lg bg-green-500/10 flex items-center justify-center group-hover:bg-green-500/20 transition-colors">
                <Users className="w-5 h-5 text-green-400" />
              </div>
              <h4 className="font-bold text-green-400 mb-2">Process Authentication</h4>
              <p className="text-sm text-slate-300 leading-relaxed">Cryptographic token generation using CSPRNG. Processes must perform a handshake to receive a session token before accessing IPC channels.</p>
            </div>
            
            <div className="bg-slate-900 p-5 rounded-xl border border-slate-700 hover:border-purple-500/30 transition-colors group">
              <div className="mb-3 w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center group-hover:bg-blue-500/20 transition-colors">
                <Shield className="w-5 h-5 text-blue-400" />
              </div>
              <h4 className="font-bold text-blue-400 mb-2">AES-256 Encryption</h4>
              <p className="text-sm text-slate-300 leading-relaxed">Payloads can be optionally encrypted using Fernet (symmetric encryption) ensuring confidentiality across shared memory segments.</p>
            </div>
            
            <div className="bg-slate-900 p-5 rounded-xl border border-slate-700 hover:border-purple-500/30 transition-colors group">
              <div className="mb-3 w-10 h-10 rounded-lg bg-orange-500/10 flex items-center justify-center group-hover:bg-orange-500/20 transition-colors">
                <FileSignature className="w-5 h-5 text-orange-400" />
              </div>
              <h4 className="font-bold text-orange-400 mb-2">HMAC Integrity</h4>
              <p className="text-sm text-slate-300 leading-relaxed">Every message is signed with HMAC-SHA256. The receiver re-computes the hash to verify the message has not been tampered with during transit.</p>
            </div>
            
            <div className="bg-slate-900 p-5 rounded-xl border border-slate-700 hover:border-purple-500/30 transition-colors group">
              <div className="mb-3 w-10 h-10 rounded-lg bg-purple-500/10 flex items-center justify-center group-hover:bg-purple-500/20 transition-colors">
                <Key className="w-5 h-5 text-purple-400" />
              </div>
              <h4 className="font-bold text-purple-400 mb-2">RBAC & Permissions</h4>
              <p className="text-sm text-slate-300 leading-relaxed">Granular Access Control Lists (ACLs) enforce 'read', 'write', or 'execute' permissions per process ID.</p>
            </div>
          </div>
        </div>
      </div>

      <div className="border-t border-slate-700 pt-8">
        <h3 className="text-xl font-bold text-white mb-6">API Endpoint Reference</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-sm">
          {[
            { method: 'POST', url: '/api/authenticate', desc: 'Register process & get token' },
            { method: 'POST', url: '/api/send', desc: 'Dispatch secure message' },
            { method: 'POST', url: '/api/receive', desc: 'Poll for incoming messages' }
          ].map((endpoint, i) => (
            <div key={i} className="bg-slate-900 rounded-lg overflow-hidden border border-slate-700">
              <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
                <span className={`font-bold ${
                  endpoint.method === 'POST' ? 'text-green-400' : 'text-blue-400'
                }`}>{endpoint.method}</span>
                <span className="text-slate-500 text-xs">JSON</span>
              </div>
              <div className="p-4">
                <div className="text-blue-300 mb-2">{endpoint.url}</div>
                <div className="text-slate-400 text-xs">{endpoint.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Documentation;
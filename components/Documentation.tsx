import React from 'react';
import { Shield, Key, FileSignature, Users, Folder, Server, Lock, Network } from 'lucide-react';

const Documentation: React.FC = () => {
  return (
    <div className="bg-slate-800 rounded-lg p-8 shadow-xl border border-slate-700 h-full overflow-y-auto">
      <div className="flex items-center gap-3 mb-8 pb-4 border-b border-slate-700">
        <Server className="w-8 h-8 text-purple-400" />
        <h2 className="text-3xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
          System Documentation
        </h2>
      </div>
      
      {/* System Architecture Diagram */}
      <div className="mb-12">
        <h3 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
          <Network className="w-5 h-5 text-blue-400" />
          Architecture Overview
        </h3>
        <div className="bg-slate-950 p-6 rounded-lg font-mono text-[10px] sm:text-xs text-slate-300 overflow-x-auto border border-slate-800 leading-relaxed whitespace-pre shadow-inner">
{`
                                     [ AUTHENTICATION LAYER (OAUTH/JWT) ]
                                                    |
+---------------------+           +---------------------------------+           +--------------------+
|   CLIENT (React)    |   HTTPS   |      API GATEWAY (Flask/Spring) |           |   KERNEL SPACE     |
+---------------------+ <-------> +---------------------------------+           +--------------------+
|  - Control Panel    |   JSON    |  [ SECURITY MODULE ]            |           |                    |
|  - Visualizer       |           |  - AES-256-GCM Encryption       |   SysCalls|  [ IPC CHANNELS ]  |
|  - Activity Logs    |           |  - HMAC-SHA256 Signing          | <-------> |  - SysV Queues     |
+---------------------+           |  - ACL Verification             |           |  - Named Pipes     |
                                  +---------------------------------+           |  - Shared Memory   |
                                                    |                           |                    |
                                          +---------v---------+                 +--------------------+
                                          |   PROCESS MANAGER |
                                          +-------------------+
`}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        <div className="col-span-1 space-y-8">
          <div>
            <h3 className="text-xl font-bold text-purple-400 mb-4 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Security Specifications
            </h3>
            <p className="text-slate-300 mb-4 text-sm leading-relaxed">
              The framework implements a Zero-Trust architecture for local process communication.
            </p>
            <ul className="space-y-3">
              {[
                { label: 'Encryption', desc: 'AES-256-GCM (Authenticated Encryption)', icon: Lock },
                { label: 'Integrity', desc: 'HMAC-SHA256 (Hash-based Message Auth)', icon: FileSignature },
                { label: 'Access Control', desc: 'Role-Based Access Control (RBAC)', icon: Key }
              ].map((item, i) => (
                <li key={i} className="flex items-start gap-3 bg-slate-900/50 p-3 rounded-lg border border-slate-700/50 group hover:border-purple-500/30 transition-colors">
                  <div className="mt-1 p-1.5 rounded bg-slate-800 group-hover:bg-purple-900/30 text-purple-400 transition-colors">
                    <item.icon className="w-4 h-4" />
                  </div>
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
            <Folder className="w-5 h-5" />
            Project Structure
          </h3>
          <div className="bg-slate-900 p-6 rounded-lg font-mono text-sm text-slate-300 border border-slate-700 h-full">
            <ul className="space-y-2">
              <li className="flex items-center gap-2 font-bold text-white"><span className="text-blue-400">secure-ipc-framework/</span></li>
              
              {/* Frontend */}
              <li className="pl-4 flex items-center gap-2"><span className="text-slate-600">├──</span> <span className="text-purple-400 font-bold">frontend/</span></li>
              <li className="pl-8 flex items-center gap-2"><span className="text-slate-600">├──</span> <span className="text-yellow-300">components/</span> <span className="text-slate-500 text-xs"># UI Widgets (ControlPanel, Visualizer)</span></li>
              <li className="pl-8 flex items-center gap-2"><span className="text-slate-600">├──</span> <span className="text-yellow-300">types/</span> <span className="text-slate-500 text-xs"># Shared Interfaces</span></li>
              <li className="pl-8 flex items-center gap-2"><span className="text-slate-600">└──</span> <span className="text-blue-300">App.tsx</span> <span className="text-slate-500 text-xs"># Main React Logic</span></li>
              
              {/* Backend */}
              <li className="pl-4 flex items-center gap-2"><span className="text-slate-600">├──</span> <span className="text-purple-400 font-bold">backend/</span></li>
              <li className="pl-8 flex items-center gap-2"><span className="text-slate-600">├──</span> <span className="text-green-400">server.py</span> <span className="text-slate-500 text-xs"># Flask API + IPC Implementation</span></li>
              <li className="pl-8 flex items-center gap-2"><span className="text-slate-600">├──</span> <span className="text-green-400">ipc_manager.py</span> <span className="text-slate-500 text-xs"># IPC Factory Classes</span></li>
              <li className="pl-8 flex items-center gap-2"><span className="text-slate-600">└──</span> <span className="text-green-400">security.py</span> <span className="text-slate-500 text-xs"># AES/HMAC Logic</span></li>

              {/* Tests */}
              <li className="pl-4 flex items-center gap-2"><span className="text-slate-600">├──</span> <span className="text-purple-400 font-bold">tests/</span></li>
              <li className="pl-8 flex items-center gap-2"><span className="text-slate-600">├──</span> <span className="text-orange-300">test_integrity.py</span> <span className="text-slate-500 text-xs"># HMAC Validation Tests</span></li>
              <li className="pl-8 flex items-center gap-2"><span className="text-slate-600">└──</span> <span className="text-orange-300">test_pipes.py</span> <span className="text-slate-500 text-xs"># FIFO Blocking Tests</span></li>
              
              <li className="pl-4 flex items-center gap-2"><span className="text-slate-600">└──</span> <span className="text-slate-400">README.md</span></li>
            </ul>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 border-t border-slate-700 pt-8">
         <div>
            <h4 className="font-bold text-white mb-2">Example: Python Security Implementation</h4>
            <div className="bg-black/50 p-4 rounded border border-slate-800 font-mono text-xs text-green-300">
               <span className="text-purple-400">def</span> <span className="text-blue-400">sign_payload</span>(key, data):<br/>
               &nbsp;&nbsp;h = hmac.new(key, data, hashlib.sha256)<br/>
               &nbsp;&nbsp;<span className="text-purple-400">return</span> h.hexdigest()
            </div>
         </div>
         <div>
            <h4 className="font-bold text-white mb-2">Example: Shared Memory Write</h4>
             <div className="bg-black/50 p-4 rounded border border-slate-800 font-mono text-xs text-blue-300">
               shm = shared_memory.SharedMemory(name=<span className="text-green-300">'secure_block'</span>)<br/>
               shm.buf[:len(data)] = data<br/>
               shm.close()
            </div>
         </div>
      </div>
    </div>
  );
};

export default Documentation;
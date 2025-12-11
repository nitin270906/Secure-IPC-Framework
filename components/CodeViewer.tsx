import React from 'react';
import { Copy, Check } from 'lucide-react';

interface CodeViewerProps {
  code: string;
  language: string;
  title: string;
  colorClass: string;
}

const CodeViewer: React.FC<CodeViewerProps> = ({ code, language, title, colorClass }) => {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-slate-800 rounded-lg p-6 shadow-xl border border-slate-700 h-full">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold">{title}</h2>
        <button
          onClick={handleCopy}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors text-sm font-medium text-slate-300"
        >
          {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
          {copied ? 'Copied!' : 'Copy Code'}
        </button>
      </div>
      <div className="relative bg-slate-900 p-6 rounded-lg overflow-auto border border-slate-800 h-[calc(100vh-300px)]">
        <pre className="text-sm font-mono leading-relaxed">
          <code className={colorClass}>{code}</code>
        </pre>
      </div>
    </div>
  );
};

export default CodeViewer;
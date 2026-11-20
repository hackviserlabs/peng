import { useState } from 'react';
import { Printer, Trash2, Copy, Link2 } from 'lucide-react';

interface EditorToolbarProps {
    onPrint: () => void;
    onDelete: () => void;
    onDuplicate: () => void;
}

export default function EditorToolbar({ onPrint, onDelete, onDuplicate }: EditorToolbarProps) {
    const [copyStatus, setCopyStatus] = useState('');

    const copyLink = async () => {
        try {
            const { origin, pathname } = window.location;
            await navigator.clipboard.writeText(origin + pathname);
            setCopyStatus('Link copied');
        } catch {
            setCopyStatus('Copy the link from the address bar');
        }
    };

    return (
        <div className="absolute top-6 right-8 flex items-center gap-3 print:hidden z-10">
            <span role="status" className="absolute right-0 top-full mt-1 whitespace-nowrap text-xs text-zinc-300">
                {copyStatus}
            </span>
            <button
                type="button"
                onClick={() => void copyLink()}
                className="flex items-center px-3 py-1.5 text-sm font-medium text-zinc-300 bg-zinc-800/50 hover:bg-zinc-700 rounded-md transition-colors border border-zinc-700/50"
            >
                <Link2 className="w-4 h-4 mr-2" /> Copy link
            </button>
            <button
                onClick={onDuplicate}
                className="flex items-center px-3 py-1.5 text-sm font-medium text-zinc-300 bg-zinc-800/50 hover:bg-zinc-700 rounded-md transition-colors border border-zinc-700/50"
                title="Duplicate Finding"
            >
                <Copy className="w-4 h-4 mr-2" /> Duplicate
            </button>
            <button
                onClick={onPrint}
                className="flex items-center px-3 py-1.5 text-sm font-medium text-zinc-300 bg-zinc-800/50 hover:bg-zinc-700 rounded-md transition-colors border border-zinc-700/50"
            >
                <Printer className="w-4 h-4 mr-2" /> Print / PDF
            </button>
            <button
                onClick={onDelete}
                className="p-1.5 text-zinc-500 hover:text-red-400 hover:bg-red-400/10 rounded-md transition-colors"
                title="Delete Finding"
            >
                <Trash2 className="w-5 h-5" />
            </button>
        </div>
    );
}

import { sanitizeRichText } from '../../lib/richText';
import { useEditor, EditorContent } from '@tiptap/react';
import { BubbleMenu } from '@tiptap/react/menus';
import { Bold, Italic, Strikethrough, Code, CodeSquare, List, ListOrdered, Link2, Unlink } from 'lucide-react';
import StarterKit from '@tiptap/starter-kit';
import Image from '@tiptap/extension-image';
import Link from '@tiptap/extension-link';
import Placeholder from '@tiptap/extension-placeholder';
import CodeBlockLowlight from '@tiptap/extension-code-block-lowlight';
import { common, createLowlight } from 'lowlight';
import { useEffect, useMemo } from 'react';

const lowlight = createLowlight(common);

function setLink(editor: ReturnType<typeof useEditor>) {
    if (!editor) return;
    const previousUrl = editor.getAttributes('link').href || '';
    const url = window.prompt('Enter URL:', previousUrl);
    if (url === null) return; // cancelled
    if (url === '') {
        editor.chain().focus().extendMarkRange('link').unsetLink().run();
        return;
    }
    editor.chain().focus().extendMarkRange('link').setLink({ href: url }).run();
}

interface RichTextEditorProps {
    content: string;
    placeholder: string;
    onChange: (value: string) => void;
}

export default function RichTextEditor({ content, placeholder, onChange }: RichTextEditorProps) {
    const cleanContent = useMemo(() => sanitizeRichText(content), [content]);
    const editor = useEditor({
        extensions: [
            StarterKit.configure({
                link: false, // configured below
                codeBlock: false, // replaced by CodeBlockLowlight
            }),
            Image.configure({
                inline: true,
                allowBase64: true,
            }),
            Link.configure({
                openOnClick: true,
                autolink: true,
                HTMLAttributes: {
                    target: '_blank',
                    rel: 'noopener noreferrer',
                },
            }),
            Placeholder.configure({
                placeholder,
                emptyEditorClass: 'is-editor-empty',
            }),
            CodeBlockLowlight.configure({
                lowlight,
                defaultLanguage: 'http',
            }),
        ],
        content: cleanContent,
        onUpdate: ({ editor }) => {
            onChange(editor.getHTML());
        },
        editorProps: {
            transformPastedHTML: sanitizeRichText,
            attributes: {
                class:
                    'w-full bg-transparent border-none text-zinc-300 print:text-black text-base leading-relaxed outline-none min-h-[72px] prose prose-invert prose-emerald max-w-none print:prose-p:text-black print:prose-headings:text-black',
            },
            handlePaste: (view, event) => {
                const items = Array.from(event.clipboardData?.items || []);
                for (const item of items) {
                    if (item.type.indexOf('image/') === 0) {
                        const file = item.getAsFile();
                        if (file) {
                            const reader = new FileReader();
                            reader.onload = (e) => {
                                const src = e.target?.result;
                                if (view.isDestroyed || typeof src !== 'string') return;
                                const node = view.state.schema.nodes.image.create({ src });
                                const transaction = view.state.tr.replaceSelectionWith(node);
                                view.dispatch(transaction);
                            };
                            reader.readAsDataURL(file);
                            return true;
                        }
                    }
                }
                return false;
            },
        },
    });

    useEffect(() => {
        if (editor && content !== editor.getHTML()) {
            if (cleanContent !== editor.getHTML()) editor.commands.setContent(cleanContent, { emitUpdate: false });
        }
    }, [content, cleanContent, editor]);

    return (
        <div className="rich-text-container relative">
            {editor && (
                <BubbleMenu editor={editor} className="flex overflow-hidden rounded-lg shadow-xl bg-zinc-800 border border-zinc-700/50 print:hidden">
                    <button
                        onClick={() => editor.chain().focus().toggleBold().run()}
                        className={`p-2 flex items-center justify-center transition-colors ${editor.isActive('bold') ? 'bg-zinc-700/80 text-emerald-400' : 'text-zinc-300 hover:bg-zinc-700 hover:text-white'}`}
                        title="Bold (Cmd+B)"
                    >
                        <Bold className="w-4 h-4" />
                    </button>
                    <button
                        onClick={() => editor.chain().focus().toggleItalic().run()}
                        className={`p-2 flex items-center justify-center transition-colors ${editor.isActive('italic') ? 'bg-zinc-700/80 text-emerald-400' : 'text-zinc-300 hover:bg-zinc-700 hover:text-white'}`}
                        title="Italic (Cmd+I)"
                    >
                        <Italic className="w-4 h-4" />
                    </button>
                    <button
                        onClick={() => editor.chain().focus().toggleStrike().run()}
                        className={`p-2 flex items-center justify-center transition-colors ${editor.isActive('strike') ? 'bg-zinc-700/80 text-emerald-400' : 'text-zinc-300 hover:bg-zinc-700 hover:text-white'}`}
                        title="Strikethrough"
                    >
                        <Strikethrough className="w-4 h-4" />
                    </button>
                    <button
                        onClick={() => editor.chain().focus().toggleCode().run()}
                        className={`p-2 flex items-center justify-center transition-colors ${editor.isActive('code') ? 'bg-zinc-700/80 text-emerald-400' : 'text-zinc-300 hover:bg-zinc-700 hover:text-white'}`}
                        title="Inline Code (Cmd+E)"
                    >
                        <Code className="w-4 h-4" />
                    </button>
                    <button
                        onClick={() => editor.chain().focus().toggleCodeBlock().run()}
                        className={`p-2 flex items-center justify-center transition-colors ${editor.isActive('codeBlock') ? 'bg-zinc-700/80 text-emerald-400' : 'text-zinc-300 hover:bg-zinc-700 hover:text-white'}`}
                        title="Code Block"
                    >
                        <CodeSquare className="w-4 h-4" />
                    </button>
                    <div className="w-px h-5 bg-zinc-700" />
                    <button
                        onClick={() => editor.chain().focus().toggleBulletList().run()}
                        className={`p-2 flex items-center justify-center transition-colors ${editor.isActive('bulletList') ? 'bg-zinc-700/80 text-emerald-400' : 'text-zinc-300 hover:bg-zinc-700 hover:text-white'}`}
                        title="Bullet List"
                    >
                        <List className="w-4 h-4" />
                    </button>
                    <button
                        onClick={() => editor.chain().focus().toggleOrderedList().run()}
                        className={`p-2 flex items-center justify-center transition-colors ${editor.isActive('orderedList') ? 'bg-zinc-700/80 text-emerald-400' : 'text-zinc-300 hover:bg-zinc-700 hover:text-white'}`}
                        title="Numbered List"
                    >
                        <ListOrdered className="w-4 h-4" />
                    </button>
                    <div className="w-px h-5 bg-zinc-700" />
                    {editor.isActive('link') ? (
                        <button
                            onClick={() => editor.chain().focus().unsetLink().run()}
                            className="p-2 flex items-center justify-center transition-colors bg-zinc-700/80 text-emerald-400"
                            title="Remove Link"
                        >
                            <Unlink className="w-4 h-4" />
                        </button>
                    ) : (
                        <button
                            onClick={() => setLink(editor)}
                            className="p-2 flex items-center justify-center transition-colors text-zinc-300 hover:bg-zinc-700 hover:text-white"
                            title="Insert Link"
                        >
                            <Link2 className="w-4 h-4" />
                        </button>
                    )}
                </BubbleMenu>
            )}
            <EditorContent editor={editor} />
        </div>
    );
}

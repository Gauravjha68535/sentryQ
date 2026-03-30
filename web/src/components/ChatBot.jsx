import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { MessageSquare, X, Send, Bot, User, Maximize2, Minimize2, Sparkles, Wand2, ShieldCheck, Zap, Info } from 'lucide-react';

const ChatBot = ({ scanId }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [isMinimized, setIsMinimized] = useState(false);
    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [showTip, setShowTip] = useState(true);
    const messagesEndRef = useRef(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    useEffect(() => {
        const handleOpenChat = (e) => {
            const { content, autoSend } = e.detail || {};
            setIsOpen(true);
            setIsMinimized(false);
            if (content) {
                setInput(content);
                if (autoSend) {
                    setTimeout(() => {
                        const sendBtn = document.querySelector('.chat-input-area .btn-primary');
                        sendBtn?.click();
                    }, 100);
                }
            }
        };

        window.addEventListener('sentryq-chat-open', handleOpenChat);
        return () => window.removeEventListener('sentryq-chat-open', handleOpenChat);
    }, [messages]);

    const handleSend = async () => {
        if (!input.trim() || isLoading) return;

        const userMsg = { role: 'user', content: input };
        setMessages(prev => [...prev, userMsg]);
        setInput('');
        setIsLoading(true);

        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    messages: [...messages.filter(m => m.role !== 'system'), userMsg],
                    scan_id: scanId
                })
            });

            if (!response.ok) throw new Error('Failed to get AI response');

            const data = await response.json();
            setMessages(prev => [...prev, data.message]);
        } catch (error) {
            setMessages(prev => [...prev, {
                role: 'assistant',
                content: "⚠️ **Connection Error**: I'm having trouble reaching my local intelligence engine. Please ensure the SentryQ backend and Ollama are active."
            }]);
        } finally {
            setIsLoading(false);
        }
    };

    const formatContent = (text) => {
        if (!text) return null;
        const blocks = text.split(/(```[\s\S]*?```)/);

        return blocks.map((block, i) => {
            if (block.startsWith('```')) {
                const code = block.replace(/```(\w+)?\n?/, '').replace(/```$/, '');
                return (
                    <pre key={i} className="chat-code-block">
                        <code>{code}</code>
                    </pre>
                );
            }

            const parts = block.split(/(\*\*.*?\*\*)/);
            return (
                <span key={i}>
                    {parts.map((part, j) => {
                        if (part.startsWith('**') && part.endsWith('**')) {
                            return <strong key={j}>{part.slice(2, -2)}</strong>;
                        }
                        return part;
                    })}
                </span>
            );
        });
    };

    return (
        <div className="chatbot-container">
            <AnimatePresence>
                {isOpen && !isMinimized && (
                    <motion.div
                        initial={{ opacity: 0, y: 30, scale: 0.9, x: 20 }}
                        animate={{ opacity: 1, y: 0, scale: 1, x: 0 }}
                        exit={{ opacity: 0, y: 30, scale: 0.9, x: 20 }}
                        transition={{ type: "spring", damping: 25, stiffness: 350 }}
                        className="chat-window"
                    >
                        <div className="chat-header">
                            <div className="flex items-center gap-3">
                                <div className="chat-avatar-small">
                                    <Sparkles size={18} />
                                </div>
                                <div className="flex flex-col">
                                    <h4>JD AI</h4>
                                    <span className="text-xs">Live Protection Active</span>
                                </div>
                            </div>
                            <div className="flex items-center gap-1">
                                <button onClick={() => setIsMinimized(true)} className="btn-icon">
                                    <Minimize2 size={18} />
                                </button>
                                <button onClick={() => setIsOpen(false)} className="btn-icon">
                                    <X size={18} />
                                </button>
                            </div>
                        </div>

                        <div className="chat-messages">
                            {messages.length === 0 && (
                                <div className="chat-empty-state">
                                    <div className="chat-avatar-large">
                                        <Bot size={36} />
                                    </div>
                                    <p>I am your dedicated Security Expert. How can I help secure your code today?</p>

                                    <div className="grid grid-cols-1 gap-3 w-full mb-6">
                                        <div className="flex items-start gap-2 p-3 bg-white/5 rounded-xl border border-white/5 text-left text-xs text-muted">
                                            <ShieldCheck size={14} className="text-success mt-0.5" />
                                            <span>Ask about specific vulnerabilities or exploit paths.</span>
                                        </div>
                                        <div className="flex items-start gap-2 p-3 bg-white/5 rounded-xl border border-white/5 text-left text-xs text-muted">
                                            <Zap size={14} className="text-yellow-500 mt-0.5" />
                                            <span>Get instant remediation code for identified flaws.</span>
                                        </div>
                                    </div>

                                    <div className="chat-suggestions">
                                        <button onClick={() => { setInput("Audit this scan for critical risks"); setTimeout(handleSend, 0); }}>"Audit Report"</button>
                                        <button onClick={() => { setInput("How to implement secure authentication?"); setTimeout(handleSend, 0); }}>"Secure Auth"</button>
                                        <button onClick={() => { setInput("Explain OWASP Top 10 risks in my code"); setTimeout(handleSend, 0); }}>"OWASP Check"</button>
                                    </div>
                                </div>
                            )}

                            {messages.map((msg, idx) => (
                                <motion.div
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    key={idx}
                                    className={`chat-message ${msg.role}`}
                                >
                                    <div className="chat-avatar">
                                        {msg.role === 'assistant' ? <Bot size={18} /> : <User size={18} />}
                                    </div>
                                    <div className="chat-content">
                                        {formatContent(msg.content)}
                                    </div>
                                </motion.div>
                            ))}

                            {isLoading && (
                                <div className="chat-message assistant">
                                    <div className="chat-avatar">
                                        <Bot size={18} />
                                    </div>
                                    <div className="chat-content">
                                        <div className="typing-indicator">
                                            <span></span><span></span><span></span>
                                        </div>
                                    </div>
                                </div>
                            )}
                            <div ref={messagesEndRef} />
                        </div>

                        <div className="chat-input-area">
                            <input
                                type="text"
                                placeholder="Query our security intelligence..."
                                value={input}
                                onChange={(e) => setInput(e.target.value)}
                                onKeyPress={(e) => e.key === 'Enter' && handleSend()}
                                className="input flex-1"
                            />
                            <button disabled={isLoading || !input.trim()} onClick={handleSend} className="btn-primary flex items-center justify-center rounded-xl px-4">
                                <Send size={18} />
                            </button>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            <motion.button
                whileHover={{ scale: 1.1, rotate: 10 }}
                whileTap={{ scale: 0.9 }}
                onClick={() => {
                    setIsOpen(prev => !prev);
                    setIsMinimized(false);
                }}
                className={`chat-toggle ${isOpen && !isMinimized ? 'hidden' : ''}`}
            >
                <Sparkles size={28} />
                {isMinimized && <span className="notification-dot"></span>}
            </motion.button>
        </div>
    );
};

export default ChatBot;

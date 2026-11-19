import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { ApiError, api, errorMessage } from '../../lib/api';

interface Session {
    username: string;
}

export interface Account extends Session {
    expired: boolean;
    signOut: () => Promise<void>;
}

export default function ConnectedWorkspace({ children }: { children: (account: Account) => ReactNode }) {
    const [session, setSession] = useState<Session | null>();
    const [expired, setExpired] = useState(false);
    const [attempt, setAttempt] = useState(0);
    const [sessionError, setSessionError] = useState<string>();

    useEffect(() => {
        let active = true;
        api<Session>('/api/session', 'Checking session').then(account => {
            if (active) setSession(account);
        }).catch(error => {
            if (!active) return;
            if (error instanceof ApiError && error.status === 401) setSession(null);
            else setSessionError(errorMessage(error));
        });
        return () => { active = false; };
    }, [attempt]);

    useEffect(() => {
        const expire = () => setExpired(true);
        window.addEventListener('workspace-session-expired', expire);
        return () => window.removeEventListener('workspace-session-expired', expire);
    }, []);

    const signIn = async (username: string, password: string) => {
        await api('/api/login', 'Signing in', 'POST', { username, password });
        const account = await api<Session>('/api/session', 'Checking session');
        if (session && account.username !== session.username) {
            await api('/api/logout', 'Signing out', 'POST');
            throw new Error('Sign in with the same account to resume your workspace.');
        }
        setSession(account);
        setExpired(false);
    };

    const signOut = async () => {
        try {
            await api('/api/logout', 'Signing out', 'POST');
        } catch (error) {
            if (!(error instanceof ApiError) || error.status !== 401) throw error;
        }
        setSession(null);
        setExpired(false);
    };

    if (session === undefined) {
        return (
            <main className="grid h-screen place-content-center gap-3 bg-zinc-950 text-sm text-zinc-300">
                {sessionError ? (
                    <>
                        <p role="alert">{sessionError}</p>
                        <button className="underline" onClick={() => { setSessionError(undefined); setAttempt(value => value + 1); }}>Retry</button>
                    </>
                ) : <p role="status">Checking session…</p>}
            </main>
        );
    }

    return (
        <>
            {session && (
                <div hidden={expired} inert={expired}>
                    {children({ username: session.username, expired, signOut })}
                </div>
            )}
            {(!session || expired) && <SignIn username={session?.username} onSignIn={signIn} />}
        </>
    );
}

function SignIn({ username: existingUsername, onSignIn }: {
    username?: string;
    onSignIn: (username: string, password: string) => Promise<void>;
}) {
    const [username, setUsername] = useState(existingUsername ?? '');
    const [password, setPassword] = useState('');
    const [error, setError] = useState<string>();
    const [busy, setBusy] = useState(false);
    const inputClass = 'w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none';

    const submit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        if (busy) return;
        setBusy(true);
        setError(undefined);
        try {
            await onSignIn(username, password);
        } catch (error) {
            setError(error instanceof ApiError && error.status === 401
                ? 'Sign-in failed. Check your username and password.'
                : errorMessage(error));
        } finally {
            setPassword('');
            setBusy(false);
        }
    };

    return (
        <main className="grid min-h-screen place-items-center bg-zinc-950 px-6 text-zinc-300">
            <form onSubmit={submit} className="w-full max-w-sm space-y-5 rounded-xl border border-zinc-800 bg-zinc-900/60 p-7">
                <div className="flex items-center gap-3">
                    <img src="/logo.svg" alt="" className="h-8 w-8" />
                    <h1 className="text-xl font-semibold text-white">Sign in to peng</h1>
                </div>
                <p className="text-sm text-zinc-400">
                    {existingUsername ? 'Your session expired. Sign in to resume your workspace.' : 'Use your account to open the connected workspace.'}
                </p>
                <label className="block space-y-1 text-sm">
                    <span>Username</span>
                    <input className={inputClass} autoComplete="username" maxLength={120} required value={username}
                        readOnly={Boolean(existingUsername)} onChange={event => setUsername(event.target.value)} />
                </label>
                <label className="block space-y-1 text-sm">
                    <span>Password</span>
                    <input className={inputClass} type="password" autoComplete="current-password" maxLength={1024} required value={password}
                        onChange={event => setPassword(event.target.value)} />
                </label>
                {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
                <button disabled={busy} className="w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-black hover:bg-emerald-400 disabled:opacity-50">
                    {busy ? 'Signing in…' : 'Sign in'}
                </button>
            </form>
        </main>
    );
}

import { errorMessage } from './api';
import { workspaceStorage as storage } from './workspaceStorage';
import type { Finding, Project } from '../types';

interface FindingList {
    findings: Finding[];
    ready: boolean;
    error?: string;
}

interface Write {
    projectId: string;
    findingId?: string;
    save: () => Promise<void>;
    timer?: ReturnType<typeof setTimeout>;
    error?: string;
}

const AUTOSAVE_DELAY = 350;

export class Workspace {
    private listeners = new Set<() => void>();
    private revision = 0;
    private writes = new Map<string, Write>();
    private sending = new Set<string>();
    private readingProjects = false;
    private findingLists = new Map<string, FindingList>();
    private findingReads = new Map<string, Set<string>>();
    private savedProjects = new Set<string>();

    projects: Project[] = [];
    projectsReady = false;
    projectsError: string | undefined;

    subscribe = (listener: () => void) => {
        this.listeners.add(listener);
        return () => { this.listeners.delete(listener); };
    };

    getSnapshot = () => this.revision;

    private changed() {
        this.revision++;
        for (const listener of this.listeners) listener();
    }

    get pending() { return this.writes.size; }
    get saveErrors() {
        return [...new Set([...this.writes.values()].flatMap(write => write.error ?? []))];
    }

    private hasPending(projectId: string) {
        return [...this.writes.values()].some(write => write.projectId === projectId);
    }

    saveStatus(projectId: string): 'saving' | 'saved' | undefined {
        const writes = [...this.writes.values()].filter(write => write.projectId === projectId);
        if (writes.length) return writes.some(write => write.error) ? undefined : 'saving';
        if (this.savedProjects.has(projectId)) return 'saved';
    }

    getFindings(projectId: string) {
        return this.findingLists.get(projectId);
    }

    async loadProjects() {
        if (this.projectsReady || this.readingProjects) return;
        this.readingProjects = true;
        this.projectsError = undefined;
        this.changed();
        try {
            this.projects = (await storage.getAllProjects())
                .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
            this.projectsReady = true;
        } catch (error) {
            this.projectsError = errorMessage(error);
        } finally {
            this.readingProjects = false;
            this.changed();
        }
    }

    async loadFindings(projectId: string) {
        if (this.findingReads.has(projectId)) return;
        const protectedIds = new Set<string>();
        for (const write of this.writes.values()) {
            if (write.projectId === projectId && write.findingId) protectedIds.add(write.findingId);
        }

        this.findingReads.set(projectId, protectedIds);
        try {
            const remote = await storage.getProjectFindings(projectId);
            if (this.findingReads.get(projectId) !== protectedIds) return;
            const current = this.getFindings(projectId);
            // Keep drafts and deletions made before or during this read. Other rows can refresh independently.
            const findings = [
                ...remote.filter(finding => !protectedIds.has(finding.id)),
                ...(current?.findings.filter(finding => protectedIds.has(finding.id)) ?? []),
            ].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
            this.findingLists.set(projectId, { findings, ready: true });
        } catch (error) {
            if (this.findingReads.get(projectId) === protectedIds) {
                const current = this.getFindings(projectId);
                this.findingLists.set(projectId, {
                    findings: [], ready: false, ...current, error: errorMessage(error),
                });
            }
        } finally {
            if (this.findingReads.get(projectId) === protectedIds) this.findingReads.delete(projectId);
            this.changed();
        }
    }

    async createProject(project: Project) {
        await storage.saveProject(project);
        this.projects = [project, ...this.projects];
        this.findingLists.set(project.id, { findings: [], ready: true });
        this.changed();
    }

    updateProject(id: string, field: keyof Project, value: string) {
        const project = this.projects.find(item => item.id === id);
        if (!project) return;
        const updated = { ...project, [field]: value, updatedAt: new Date().toISOString() };
        this.projects = this.projects.map(item => item.id === id ? updated : item);
        this.queue(`project/${id}`, id, () => storage.saveProject(updated));
    }

    async deleteProject(id: string) {
        if (this.hasPending(id)) throw new Error('Finish saving this project before deleting it.');
        await storage.deleteProject(id);
        this.projects = this.projects.filter(project => project.id !== id);
        this.findingLists.delete(id);
        this.findingReads.delete(id);
        this.savedProjects.delete(id);
        this.changed();
    }

    addFinding(finding: Finding) {
        this.changeFinding(finding.projectId, finding.id, finding);
    }

    updateFinding(projectId: string, id: string, field: keyof Finding, value: string) {
        const finding = this.getFindings(projectId)?.findings.find(item => item.id === id);
        if (finding) this.changeFinding(projectId, id, { ...finding, [field]: value });
    }

    deleteFinding(projectId: string, id: string) {
        this.changeFinding(projectId, id, null);
    }

    private changeFinding(projectId: string, id: string, finding: Finding | null) {
        const list = this.getFindings(projectId);
        if (!list?.ready) return;
        const existing = list.findings.some(item => item.id === id);
        const findings = finding
            ? existing
                ? list.findings.map(item => item.id === id ? finding : item)
                : [finding, ...list.findings]
            : list.findings.filter(item => item.id !== id);
        this.findingLists.set(projectId, { ...list, findings });
        this.findingReads.get(projectId)?.add(id);
        this.queue(`project/${projectId}/finding/${id}`, projectId, () => finding
            ? storage.saveFinding(finding)
            : storage.deleteFinding(projectId, id), id);
    }

    private queue(key: string, projectId: string, save: Write['save'], findingId?: string) {
        const previous = this.writes.get(key);
        clearTimeout(previous?.timer);
        const write: Write = { projectId, findingId, save };
        write.timer = setTimeout(() => {
            write.timer = undefined;
            void this.send(key);
        }, AUTOSAVE_DELAY);
        this.writes.set(key, write);
        this.changed();
    }

    private async send(key: string) {
        const write = this.writes.get(key);
        if (!write || write.timer || write.error || this.sending.has(key)) return;
        this.sending.add(key);

        try {
            await write.save();
            this.savedProjects.add(write.projectId);
            if (this.writes.get(key) === write) this.writes.delete(key);
        } catch (error) {
            if (this.writes.get(key) === write) write.error = errorMessage(error);
        } finally {
            this.sending.delete(key);
            this.changed();
            if (this.writes.get(key) !== write) void this.send(key);
        }
    }

    retrySaves() {
        for (const [key, write] of this.writes) {
            if (!write.error) continue;
            write.error = undefined;
            void this.send(key);
        }
        this.changed();
    }
}

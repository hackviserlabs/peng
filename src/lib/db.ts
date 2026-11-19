import { openDB, type DBSchema, type IDBPDatabase } from 'idb';
import type { Finding, Project } from '../types';

interface PengDB extends DBSchema {
    projects: {
        key: string;
        value: Project;
    };
    findings: {
        key: string;
        value: Finding;
        indexes: { projectId: string };
    };
}

const DB_NAME = 'peng-db';
const DB_VERSION = 3;

let dbPromise: Promise<IDBPDatabase<PengDB>> | null = null;

function getDB() {
    if (!dbPromise) {
        dbPromise = openDB<PengDB>(DB_NAME, DB_VERSION, {
            upgrade(db, _oldVersion, _newVersion, transaction) {
                const findings = db.objectStoreNames.contains('findings')
                    ? transaction.objectStore('findings')
                    : db.createObjectStore('findings', { keyPath: 'id' });
                if (!findings.indexNames.contains('projectId')) {
                    findings.createIndex('projectId', 'projectId');
                }
                if (!db.objectStoreNames.contains('projects')) {
                    db.createObjectStore('projects', { keyPath: 'id' });
                }
            },
        }).catch(error => {
            dbPromise = null;
            throw error;
        });
    }
    return dbPromise;
}

// --- Projects ---

export async function getAllProjects(): Promise<Project[]> {
    const db = await getDB();
    return db.getAll('projects');
}

export async function saveProject(project: Project): Promise<void> {
    const db = await getDB();
    await db.put('projects', project);
}

export async function deleteProject(id: string): Promise<void> {
    const db = await getDB();
    const tx = db.transaction(['projects', 'findings'], 'readwrite');
    await tx.objectStore('projects').delete(id);
    const index = tx.objectStore('findings').index('projectId');
    let cursor = await index.openCursor(id);
    while (cursor) {
        await cursor.delete();
        cursor = await cursor.continue();
    }
    await tx.done;
}

// --- Findings (project-scoped) ---

export async function getProjectFindings(projectId: string): Promise<Finding[]> {
    const db = await getDB();
    return db.getAllFromIndex('findings', 'projectId', projectId);
}

export async function saveFinding(finding: Finding): Promise<void> {
    const db = await getDB();
    const tx = db.transaction(['projects', 'findings'], 'readwrite');
    const project = await tx.objectStore('projects').getKey(finding.projectId);
    if (!project) throw new Error('The local project no longer exists.');
    await tx.objectStore('findings').put(finding);
    await tx.done;
}

export async function deleteFinding(projectId: string, id: string): Promise<void> {
    const db = await getDB();
    const tx = db.transaction('findings', 'readwrite');
    const finding = await tx.store.get(id);
    if (finding?.projectId === projectId) await tx.store.delete(id);
    await tx.done;
}

import { api, projectPath, serverMode } from './api';
import * as db from './db';
import type { Finding, Project } from '../types';

export const workspaceStorage = serverMode ? {
    getAllProjects: () => api<Project[]>('/api/projects', 'Loading projects'),
    saveProject: (project: Project) => api(projectPath(project.id), 'Saving project', 'PUT', project),
    deleteProject: (id: string) => api(projectPath(id), 'Deleting project', 'DELETE'),
    getProjectFindings: (id: string) => api<Finding[]>(`${projectPath(id)}/findings`, 'Loading findings'),
    saveFinding: (finding: Finding) => api(
        `${projectPath(finding.projectId)}/findings/${encodeURIComponent(finding.id)}`,
        'Saving finding', 'PUT',
        'confidence' in finding && finding.confidence === undefined
            ? { ...finding, confidence: null }
            : finding,
    ),
    deleteFinding: (projectId: string, id: string) => api(
        `${projectPath(projectId)}/findings/${encodeURIComponent(id)}`, 'Deleting finding', 'DELETE',
    ),
} : db;

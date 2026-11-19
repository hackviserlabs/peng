import { useState, useEffect, useSyncExternalStore } from 'react';
import ConfirmModal from './components/ui/ConfirmModal';
import Sidebar from './components/sidebar/Sidebar';
import Editor from './components/editor/Editor';
import ProjectSettings from './components/settings/ProjectSettings';
import ProjectDashboard from './components/dashboard/ProjectDashboard';
import ReportPreview from './components/report/ReportPreview';
import TemplateBrowser from './components/templates/TemplateBrowser';
import { Workspace } from './lib/workspace';
import { parseProjectImport } from './lib/projectImport';
import { errorMessage, serverMode } from './lib/api';
import ConnectedWorkspace, { type Account } from './components/workspace/ConnectedWorkspace';
import type { Finding, Project } from './types';
import { createDefaultFinding, createDefaultProject } from './types';
import type { FindingTemplate } from './constants';

type ActiveView = 'editor' | 'settings';

export default function App() {
  return serverMode ? <ConnectedWorkspace>{(account) => <WorkspaceView account={account} />}</ConnectedWorkspace>
    : <WorkspaceView />;
}

function WorkspaceView({ account }: { account?: Account }) {
  const [workspace] = useState(() => new Workspace());
  useSyncExternalStore(workspace.subscribe, workspace.getSnapshot);
  const { projects, pending, saveErrors } = workspace;
  const expired = account?.expired ?? false;
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null);
  const findingList = activeProjectId ? workspace.getFindings(activeProjectId) : undefined;
  const findings = findingList?.findings ?? [];
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string>();
  const [pendingDeleteFindingId, setPendingDeleteFindingId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [activeView, setActiveView] = useState<ActiveView>('editor');
  const [showReport, setShowReport] = useState(false);
  const [showTemplateBrowser, setShowTemplateBrowser] = useState(false);

  useEffect(() => {
    if (!expired) void workspace.loadProjects();
  }, [workspace, expired]);

  useEffect(() => {
    if (!activeProjectId || expired) return;
    const refresh = () => void workspace.loadFindings(activeProjectId);
    refresh();
    if (!serverMode) return;
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') refresh();
    }, 5000);
    window.addEventListener('focus', refresh);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('focus', refresh);
    };
  }, [workspace, activeProjectId, expired]);

  useEffect(() => {
    if (activeProjectId || expired) return;
    for (const project of projects) void workspace.loadFindings(project.id);
  }, [workspace, projects, activeProjectId, expired]);

  useEffect(() => {
    if (!pending && !busy) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [pending, busy]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Cmd+T / Ctrl+T → Toggle template browser
      if ((e.metaKey || e.ctrlKey) && e.key === 't' && findingList?.ready && !expired) {
        e.preventDefault();
        setShowTemplateBrowser((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [findingList?.ready, expired]);

  const activeProject = projects.find((p) => p.id === activeProjectId) ?? null;

  // --- Finding handlers ---

  const handleAddFinding = (template: FindingTemplate | null = null) => {
    if (!activeProjectId || !findingList?.ready) return;
    const base = createDefaultFinding(activeProjectId);
    const newFinding: Finding = template
      ? {
        ...base,
        title: template.title,
        severity: template.severity,
        description: template.description,
        impact: template.impact,
        remediation: template.remediation,
        cwe: template.cwe ?? '',
        cvss: template.cvss ?? '',
        references: template.references ?? '',
        url: template.url ?? '',
        method: template.method ?? '',
        parameter: template.parameter ?? '',
        affectedHost: template.affectedHost ?? '',
        port: template.port ?? '',
      }
      : base;
    workspace.addFinding(newFinding);
    setSelectedFindingId(newFinding.id);
    setActiveView('editor');
  };

  const handleSelectFinding = (id: string) => {
    setSelectedFindingId(id);
    setActiveView('editor');
  };

  const handleDeleteFinding = (id: string) => {
    setPendingDeleteFindingId(id);
  };

  const confirmDeleteFinding = () => {
    if (activeProjectId && pendingDeleteFindingId) {
      workspace.deleteFinding(activeProjectId, pendingDeleteFindingId);
      if (selectedFindingId === pendingDeleteFindingId) setSelectedFindingId(null);
      setPendingDeleteFindingId(null);
    }
  };

  const handleDuplicateFinding = (id: string) => {
    const original = findings.find((f) => f.id === id);
    if (!original) return;
    const duplicate: Finding = {
      ...original,
      id: crypto.randomUUID(),
      title: `${original.title} (Copy)`,
      createdAt: new Date().toISOString(),
    };
    workspace.addFinding(duplicate);
    setSelectedFindingId(duplicate.id);
  };

  const handleUpdateFinding = (field: keyof Finding, value: string) => {
    if (activeProjectId && selectedFindingId) {
      workspace.updateFinding(activeProjectId, selectedFindingId, field, value);
    }
  };

  // --- Project handlers ---

  const handleSelectProject = (id: string) => {
    setActiveProjectId(id);
    setSelectedFindingId(null);
    setSearchTerm('');
    setActiveView('editor');
  };

  const handleBackToProjects = () => {
    setActiveProjectId(null);
    setSelectedFindingId(null);
    setPendingDeleteFindingId(null);
    setShowTemplateBrowser(false);
    setShowReport(false);
    setSearchTerm('');
  };

  const handleUpdateProject = (field: keyof Project, value: string) => {
    if (activeProjectId) workspace.updateProject(activeProjectId, field, value);
  };

  const runAction = async (action: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    setActionError(undefined);
    try {
      await action();
    } catch (error) {
      setActionError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  };

  const handleCreateProject = (name: string) => runAction(async () => {
    const project = createDefaultProject(name);
    await workspace.createProject(project);
    handleSelectProject(project.id);
  });

  // --- Export / Import ---

  const exportData = () => {
    if (!activeProject) return;
    const exportPayload = { project: activeProject, findings };
    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    const name = activeProject.name || 'peng-report';
    link.download = `${name.replace(/\s+/g, '-').toLowerCase()}-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const importData = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    void runAction(async () => {
      const { project, findings: importedFindings } = parseProjectImport(await file.text());
      await workspace.createProject(project);
      for (const finding of [...importedFindings].reverse()) workspace.addFinding(finding);
      handleSelectProject(project.id);
    });
  };

  const notices = (
    <>
      {saveErrors.length > 0 && (
        <div role="alert" className="flex items-center justify-between gap-4 bg-red-950 px-5 py-2 text-sm text-red-100">
          <span>{saveErrors.join(' ')} Your unsaved changes are still in this workspace.</span>
          <button type="button" onClick={() => workspace.retrySaves()} className="shrink-0 underline">Retry saves</button>
        </div>
      )}
      {!activeProjectId && pending > 0 && saveErrors.length === 0 && (
        <p role="status" className="bg-zinc-900 px-5 py-2 text-sm text-zinc-300">Saving changes…</p>
      )}
      {actionError && <p role="alert" className="bg-red-950 px-5 py-2 text-sm text-red-100">{actionError}</p>}
    </>
  );

  if (!workspace.projectsReady) {
    return (
      <div className="grid h-screen place-content-center gap-3 bg-zinc-950 text-sm text-zinc-300">
        {workspace.projectsError ? (
          <>
            <p role="alert">{workspace.projectsError}</p>
            <button onClick={() => void workspace.loadProjects()} className="underline">Retry</button>
          </>
        ) : <p role="status">Loading projects…</p>}
      </div>
    );
  }

  if (!activeProjectId || !activeProject) {
    return (
      <div className="flex h-screen flex-col bg-zinc-950">
        {notices}
        <ProjectDashboard
          projects={projects}
          getFindings={(id) => workspace.getFindings(id)?.findings}
          getFindingsError={(id) => workspace.getFindings(id)?.error}
          onRetryFindings={(id) => void workspace.loadFindings(id)}
          busy={busy}
          account={account?.username}
          signOutDisabled={Boolean(pending) || busy}
          onSignOut={account && (() => {
            if (!workspace.pending) void runAction(account.signOut);
          })}
          onSelectProject={handleSelectProject}
          onCreateProject={handleCreateProject}
          onDeleteProject={(id) => void runAction(() => workspace.deleteProject(id))}
          onImport={importData}
        />
      </div>
    );
  }

  const filteredFindings = findings.filter((f) =>
    f.title.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const selectedFinding = findings.find((f) => f.id === selectedFindingId) ?? null;

  return (
    <div className="flex h-screen flex-col bg-[#09090b] text-zinc-300 font-sans selection:bg-emerald-500/30">
      <div className="print:hidden">
        {notices}
        {findingList?.error && (
          <div role="alert" className="flex items-center justify-between bg-red-950 px-5 py-2 text-sm text-red-100">
            {findingList.error}
            <button onClick={() => void workspace.loadFindings(activeProjectId)} className="underline">Retry</button>
          </div>
        )}
      </div>
      <div className="flex min-h-0 flex-1">
        <Sidebar
          projectName={activeProject.name}
          findings={filteredFindings}
          selectedFindingId={activeView === 'editor' ? selectedFindingId : null}
          activeView={activeView}
          searchTerm={searchTerm}
          saveStatus={workspace.saveStatus(activeProjectId)}
          onSearchChange={setSearchTerm}
          onSelectFinding={handleSelectFinding}
          onAddFinding={() => handleAddFinding()}
          onBrowseTemplates={() => findingList?.ready && setShowTemplateBrowser(true)}
          onOpenSettings={() => setActiveView('settings')}
          onExport={() => findingList?.ready && exportData()}
          onBackToProjects={handleBackToProjects}
          onGenerateReport={() => findingList?.ready && setShowReport(true)}
          onDeleteFinding={handleDeleteFinding}
          onDuplicateFinding={handleDuplicateFinding}
        />
        {activeView === 'settings' && !expired ? (
          <ProjectSettings
            project={activeProject}
            onUpdate={handleUpdateProject}
          />
        ) : !findingList?.ready ? (
          <div className="grid flex-1 place-items-center text-sm text-zinc-400">
            {findingList?.error ? 'Findings are unavailable.' : 'Loading findings…'}
          </div>
        ) : (
          <Editor
            key={selectedFindingId ?? 'empty'}
            selectedFinding={selectedFinding}
            onUpdateField={handleUpdateFinding}
            onDelete={handleDeleteFinding}
            onDuplicate={handleDuplicateFinding}
          />
        )}
      </div>
      {showReport && (
        <ReportPreview
          project={activeProject}
          findings={findings}
          onClose={() => setShowReport(false)}
        />
      )}
      {showTemplateBrowser && (
        <TemplateBrowser
          onSelect={(template) => handleAddFinding(template)}
          onClose={() => setShowTemplateBrowser(false)}
        />
      )}
      <ConfirmModal
        open={!!pendingDeleteFindingId}
        title="Delete Finding"
        message="This finding will be permanently deleted. This action cannot be undone."
        confirmLabel="Delete"
        onConfirm={confirmDeleteFinding}
        onCancel={() => setPendingDeleteFindingId(null)}
      />
    </div>
  );
}

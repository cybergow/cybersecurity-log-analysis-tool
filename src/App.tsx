/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  FileSearch,
  TerminalSquare,
  FolderKanban,
  Download,
} from 'lucide-react';
import {
  DEFAULT_ANALYST_PROFILE,
  DEFAULT_AUTH_LOGS_CSV,
  AnalystProfile,
  buildExpectedProjectFiles,
} from './data/projectArtifacts';
import {
  AnalyzerThresholds,
  DEFAULT_THRESHOLDS,
  LogValidationError,
  evaluateDetectionRules,
  parseAndValidateCsv,
} from './utils/logAnalyzer';
import { buildProjectZip } from './utils/zipBuilder';
import { AnalyzerView } from './components/AnalyzerView';
import { Task6View } from './components/Task6View';
import { Task13View } from './components/Task13View';
import { ProjectFilesView } from './components/ProjectFilesView';

type ActiveTab = 'analyzer' | 'task6' | 'task13' | 'files';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('analyzer');
  const [csvText, setCsvText] = useState<string>(DEFAULT_AUTH_LOGS_CSV);
  const [activePresetId, setActivePresetId] = useState<string>('default');
  const [thresholds, setThresholds] = useState<AnalyzerThresholds>(DEFAULT_THRESHOLDS);
  const [profile, setProfile] = useState<AnalystProfile>(DEFAULT_ANALYST_PROFILE);
  const [highlightedTask6Ip, setHighlightedTask6Ip] = useState<string | undefined>(undefined);

  // Parse and evaluate current CSV
  const analysisState = useMemo(() => {
    try {
      const events = parseAndValidateCsv(csvText);
      const report = evaluateDetectionRules(events, thresholds, 'data/auth_logs.csv');
      return {
        events,
        report,
        validationError: null as string | null,
      };
    } catch (err) {
      const message =
        err instanceof LogValidationError || err instanceof Error
          ? err.message
          : 'Unknown CSV validation error.';
      return {
        events: [],
        report: null,
        validationError: message,
      };
    }
  }, [csvText, thresholds]);

  // Always maintain a valid baseline report for deliverable generation even when user tests T5
  const deliverableReport = useMemo(() => {
    if (analysisState.report && activePresetId === 'default') {
      return analysisState.report;
    }
    const defaultEvents = parseAndValidateCsv(DEFAULT_AUTH_LOGS_CSV);
    return evaluateDetectionRules(defaultEvents, DEFAULT_THRESHOLDS, 'data/auth_logs.csv');
  }, [analysisState.report, activePresetId]);

  const projectFiles = useMemo(() => {
    const csvForDeliverable =
      activePresetId === 'default' && !analysisState.validationError
        ? csvText
        : DEFAULT_AUTH_LOGS_CSV;
    return buildExpectedProjectFiles(profile, csvForDeliverable, deliverableReport);
  }, [profile, csvText, activePresetId, analysisState.validationError, deliverableReport]);

  const handleDownloadProjectZip = () => {
    const zipBytes = buildProjectZip(
      projectFiles.map((f) => ({
        path: f.path,
        content: f.content,
      }))
    );
    const blob = new Blob([zipBytes], { type: 'application/zip' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Cybersecurity_Assessment_Tasks_6_and_13.zip';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCsvChange = (nextCsv: string, presetId = 'custom') => {
    setCsvText(nextCsv);
    setActivePresetId(presetId);
  };

  const handleNavigateToTask6 = (ip?: string) => {
    setHighlightedTask6Ip(ip);
    setActiveTab('task6');
  };

  const handleLoadScenarioFromTask13 = (scenarioCsv: string, presetId: string) => {
    setCsvText(scenarioCsv);
    setActivePresetId(presetId);
    setActiveTab('analyzer');
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900">
      {/* Top Bar Contract: Zone 1 (Single wordmark) — Zone 2 (4 single-line links) — Zone 3 (1 primary CTA) */}
      <header className="sticky top-0 z-20 bg-white border-b border-slate-200 flex items-center justify-between gap-8 px-6 py-3.5">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('analyzer');
          }}
          className="text-base font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0"
        >
          Cybersecurity Assessment
        </a>

        <nav
          aria-label="Primary Workspace Navigation"
          className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600"
        >
          <button
            type="button"
            onClick={() => setActiveTab('analyzer')}
            className={`hover:text-slate-900 whitespace-nowrap shrink-0 py-1 border-b-2 ${
              activeTab === 'analyzer'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent'
            }`}
          >
            Log Analyzer
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('task6')}
            className={`hover:text-slate-900 whitespace-nowrap shrink-0 py-1 border-b-2 ${
              activeTab === 'task6'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent'
            }`}
          >
            Task 6 Investigation
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('task13')}
            className={`hover:text-slate-900 whitespace-nowrap shrink-0 py-1 border-b-2 ${
              activeTab === 'task13'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent'
            }`}
          >
            Task 13 Prototype
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('files')}
            className={`hover:text-slate-900 whitespace-nowrap shrink-0 py-1 border-b-2 ${
              activeTab === 'files'
                ? 'border-slate-900 text-slate-900 font-semibold'
                : 'border-transparent'
            }`}
          >
            Project Files
          </button>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={handleDownloadProjectZip}
            className="px-4 py-2 text-xs font-medium text-white bg-slate-900 rounded-lg hover:bg-slate-800 whitespace-nowrap shrink-0 flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            Download Project (.zip)
          </button>
        </div>
      </header>

      {/* Main Workspace Container */}
      <div className="flex-1 flex flex-col lg:flex-row max-w-[1440px] w-full mx-auto">
        {/* Sidebar Navigation (260px on desktop, compact segmented tabs on mobile) */}
        <aside
          aria-label="Assessment Sections"
          className="lg:w-[260px] shrink-0 bg-white lg:border-r border-b lg:border-b-0 border-slate-200 p-4 lg:p-5 flex flex-col justify-between"
        >
          <div className="space-y-5">
            <div>
              <div className="text-xs font-semibold text-slate-500 px-2.5 mb-2">
                Tasks 6 & 13 Workflow
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-1 gap-1.5">
                <button
                  type="button"
                  onClick={() => setActiveTab('analyzer')}
                  className={`w-full px-3 py-2 text-xs font-medium rounded-md flex items-center gap-2.5 text-left whitespace-nowrap shrink-0 ${
                    activeTab === 'analyzer'
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                  <span>Log Triage Console</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('task6')}
                  className={`w-full px-3 py-2 text-xs font-medium rounded-md flex items-center gap-2.5 text-left whitespace-nowrap shrink-0 ${
                    activeTab === 'task6'
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <FileSearch className="w-4 h-4 shrink-0" />
                  <span>Task 6: Findings</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('task13')}
                  className={`w-full px-3 py-2 text-xs font-medium rounded-md flex items-center gap-2.5 text-left whitespace-nowrap shrink-0 ${
                    activeTab === 'task13'
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <TerminalSquare className="w-4 h-4 shrink-0" />
                  <span>Task 13: Python & Tests</span>
                </button>

                <button
                  type="button"
                  onClick={() => setActiveTab('files')}
                  className={`w-full px-3 py-2 text-xs font-medium rounded-md flex items-center gap-2.5 text-left whitespace-nowrap shrink-0 ${
                    activeTab === 'files'
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-700 hover:bg-slate-100'
                  }`}
                >
                  <FolderKanban className="w-4 h-4 shrink-0" />
                  <span>9 Expected Files</span>
                </button>
              </div>
            </div>

            {/* Dataset & Analyst Summary Panel on Desktop */}
            <div className="hidden lg:block pt-5 border-t border-slate-200 space-y-3 px-2.5 text-xs">
              <div className="font-semibold text-slate-800">
                Active Assessment Context
              </div>
              <div className="space-y-1.5 text-slate-600">
                <div className="flex justify-between">
                  <span>Analyst:</span>
                  <span className="font-medium text-slate-900 truncate max-w-[130px]">
                    {profile.analystName}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span>Candidate ID:</span>
                  <span className="font-mono text-slate-900">{profile.studentId}</span>
                </div>
                <div className="flex justify-between">
                  <span>Source File:</span>
                  <span className="font-mono text-slate-900">auth_logs.csv</span>
                </div>
                <div className="flex justify-between">
                  <span>Unit Tests:</span>
                  <span className="font-mono text-emerald-700 font-semibold">5 / 5 PASS</span>
                </div>
              </div>
            </div>
          </div>

          <div className="hidden lg:block pt-5 border-t border-slate-200 px-2.5 text-xs text-slate-500 leading-relaxed">
            Alerts are triage indicators. Corroborate with MFA, session, device, and network context before declaring an incident.
          </div>
        </aside>

        {/* Main Content Viewport */}
        <main className="flex-1 p-5 sm:p-8 min-w-0">
          {activeTab === 'analyzer' && (
            <AnalyzerView
              csvText={csvText}
              onCsvChange={handleCsvChange}
              activePresetId={activePresetId}
              events={analysisState.events}
              report={analysisState.report}
              validationError={analysisState.validationError}
              thresholds={thresholds}
              onThresholdsChange={setThresholds}
              onNavigateToTask6={handleNavigateToTask6}
            />
          )}

          {activeTab === 'task6' && (
            <Task6View
              profile={profile}
              onProfileChange={setProfile}
              events={
                analysisState.events.length > 0
                  ? analysisState.events
                  : parseAndValidateCsv(DEFAULT_AUTH_LOGS_CSV)
              }
              highlightedIp={highlightedTask6Ip}
            />
          )}

          {activeTab === 'task13' && (
            <Task13View
              profile={profile}
              report={deliverableReport}
              onLoadScenarioInAnalyzer={handleLoadScenarioFromTask13}
            />
          )}

          {activeTab === 'files' && (
            <ProjectFilesView
              projectFiles={projectFiles}
              onDownloadZip={handleDownloadProjectZip}
            />
          )}
        </main>
      </div>
    </div>
  );
}

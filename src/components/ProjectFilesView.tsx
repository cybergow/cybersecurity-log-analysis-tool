import React, { useState } from 'react';
import {
  Download,
  Copy,
  Check,
  FolderArchive,
  FileText,
  BookOpen,
} from 'lucide-react';
import { ExpectedProjectFile } from '../data/projectArtifacts';

interface ProjectFilesViewProps {
  projectFiles: ExpectedProjectFile[];
  onDownloadZip: () => void;
}

const SUBMISSION_CHECKLIST = [
  {
    id: 'chk-1',
    label: 'Run the analyzer and tests on your own computer.',
    cmd: 'python src/log_analyzer.py --input data/auth_logs.csv --output reports/analysis_results.json && python -m unittest discover -s tests -v',
  },
  {
    id: 'chk-2',
    label: 'Review the JSON and verify alerts against the CSV rows.',
    cmd: 'Open reports/analysis_results.json and confirm R1, R2, R3, R4 match data/auth_logs.csv.',
  },
  {
    id: 'chk-3',
    label: 'Personalize reports with your name and required academic details.',
    cmd: 'Configured in Task 6 & Task 13 report headers.',
  },
  {
    id: 'chk-4',
    label: 'Add your own screenshots and accurately record test results.',
    cmd: 'Capture terminal analyzer run, JSON report in VS Code, and unittest output.',
  },
  {
    id: 'chk-5',
    label: 'Keep Task 6 findings and Task 13 implementation as separate deliverables.',
    cmd: 'Task 6: reports/task6_findings.md · Task 13: src/, tests/, reports/task13_tool_report.md.',
  },
  {
    id: 'chk-6',
    label: 'Upload to GitHub or Google Drive and test the link in a private/incognito browser window.',
    cmd: 'Verify repository or shared folder permissions before submission.',
  },
  {
    id: 'chk-7',
    label: 'Submit both tasks through the designated Google Form before the deadline.',
    cmd: 'Include the Short Explanation for the Evaluator if requested.',
  },
];

const EVALUATOR_PITCH =
  'For Task 6, I analyzed synthetic authentication logs and documented suspicious patterns while separating evidence from assumptions. For Task 13, I implemented a Python command-line analyzer that checks the same data against four defensive rules, produces JSON alerts, and includes unit tests. The alerts are triage indicators, so I recommend checking MFA, session, device, and network context before deciding whether an incident occurred.';

export const ProjectFilesView: React.FC<ProjectFilesViewProps> = ({
  projectFiles,
  onDownloadZip,
}) => {
  const [selectedFilePath, setSelectedFilePath] = useState<string>(
    projectFiles[0]?.path ?? 'README.md'
  );
  const [copiedFile, setCopiedFile] = useState(false);
  const [copiedPitch, setCopiedPitch] = useState(false);
  const [showPdfPreview, setShowPdfPreview] = useState(false);
  const [checkedItems, setCheckedItems] = useState<Record<string, boolean>>({
    'chk-1': true,
    'chk-2': true,
    'chk-3': true,
  });

  const activeFile =
    projectFiles.find((f) => f.path === selectedFilePath) ?? projectFiles[0];

  const handleCopyFileContent = () => {
    if (!activeFile) return;
    navigator.clipboard?.writeText(activeFile.content);
    setCopiedFile(true);
    setTimeout(() => setCopiedFile(false), 1800);
  };

  const handleDownloadSingleFile = (file: ExpectedProjectFile) => {
    const blob = new Blob([file.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const filename = file.path.split('/').pop() ?? 'file.txt';
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyPitch = () => {
    navigator.clipboard?.writeText(EVALUATOR_PITCH);
    setCopiedPitch(true);
    setTimeout(() => setCopiedPitch(false), 1800);
  };

  return (
    <div className="space-y-8">
      {/* Header & ZIP Export Banner */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="text-xs text-slate-500 mb-1">
              <span>Section 10, 11, 12 & 13</span>
              <span aria-hidden="true" className="mx-1.5">·</span>
              <span>9 Expected Project Files</span>
              <span aria-hidden="true" className="mx-1.5">·</span>
              <span>Ready for VS Code on Windows</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">
              Project Deliverables, File Explorer & Submission Checklist
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setShowPdfPreview((v) => !v)}
              className="px-3.5 py-2 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <BookOpen className="w-3.5 h-3.5" />
              {showPdfPreview ? 'Hide Assessment PDF' : 'View Reference PDF'}
            </button>
            <button
              type="button"
              onClick={onDownloadZip}
              className="px-4 py-2 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <FolderArchive className="w-3.5 h-3.5" />
              Download Complete Project (.zip)
            </button>
          </div>
        </div>

        {/* Embedded Reference PDF Collapse */}
        {showPdfPreview && (
          <div className="mt-5 pt-5 border-t border-slate-200">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-700">
                Attached Specification: Cybersecurity_Tasks_6_and_13_Complete_Workflow.pdf
              </span>
              <a
                href="/assets/aistudio/Cybersecurity_Tasks_6_and_13_Complete_Workflow_12dc06a8.pdf"
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-700 hover:underline font-medium"
              >
                Open PDF in New Tab
              </a>
            </div>
            <iframe
              title="Cybersecurity Assessment Tasks 6 and 13 PDF"
              src="/assets/aistudio/Cybersecurity_Tasks_6_and_13_Complete_Workflow_12dc06a8.pdf"
              className="w-full h-[540px] border border-slate-200 rounded-md bg-slate-100"
            />
          </div>
        )}
      </section>

      {/* Section 10: Expected Project Files Interactive Table & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left 5 cols: 9 Expected Project Files List */}
        <section className="lg:col-span-5 bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="p-5 border-b border-slate-200">
            <h3 className="text-base font-bold text-slate-900">
              01. Expected Project Files (Section 10)
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Select any file below to inspect, copy, or download its content.
            </p>
          </div>

          <div className="divide-y divide-slate-200">
            {projectFiles.map((file) => {
              const isSelected = file.path === activeFile?.path;
              return (
                <div
                  key={file.path}
                  className={`p-3.5 flex items-center justify-between gap-3 transition-colors ${
                    isSelected ? 'bg-slate-100/90' : 'hover:bg-slate-50'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => setSelectedFilePath(file.path)}
                    className="flex-1 text-left min-w-0"
                  >
                    <div className="flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      <span className="text-xs font-mono font-bold text-slate-900 truncate">
                        {file.path}
                      </span>
                    </div>
                    <div className="text-xs text-slate-500 mt-0.5 pl-5.5">
                      <span>{file.purpose}</span>
                      <span aria-hidden="true" className="mx-1">·</span>
                      <span className="text-slate-700 font-medium">{file.deliverableTask}</span>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleDownloadSingleFile(file)}
                    aria-label={`Download ${file.path}`}
                    className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-white border border-slate-200 hover:bg-slate-100 rounded transition-colors shrink-0"
                  >
                    Download
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        {/* Right 7 cols: Selected File Content Viewer */}
        {activeFile && (
          <section className="lg:col-span-7 bg-white border border-slate-200 rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
              <div>
                <div className="text-xs text-slate-500">
                  <span>{activeFile.deliverableTask} Deliverable</span>
                  <span aria-hidden="true" className="mx-1.5">·</span>
                  <span>{activeFile.purpose}</span>
                </div>
                <h3 className="text-sm font-bold text-slate-900 font-mono mt-0.5">
                  {activeFile.path}
                </h3>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleCopyFileContent}
                  className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  {copiedFile ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      Copy File
                    </>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => handleDownloadSingleFile(activeFile)}
                  className="px-3 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5" />
                  Save File
                </button>
              </div>
            </div>

            <pre className="p-5 bg-slate-950 text-slate-100 font-mono text-xs overflow-x-auto max-h-[540px] whitespace-pre-wrap leading-relaxed">
              {activeFile.content}
            </pre>
          </section>
        )}
      </div>

      {/* Section 13: Short Explanation for Evaluator & Section 11: Limitations */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <section className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6 space-y-5">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                02. Short Explanation for the Evaluator (Section 13)
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Ready-to-submit summary statement aligning Task 6 and Task 13.
              </p>
            </div>
            <button
              type="button"
              onClick={handleCopyPitch}
              className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              {copiedPitch ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  Copied Statement
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Copy Statement
                </>
              )}
            </button>
          </div>

          <blockquote className="p-4 bg-slate-50 border border-slate-200 rounded-md text-xs text-slate-800 leading-relaxed">
            &ldquo;{EVALUATOR_PITCH}&rdquo;
          </blockquote>

          <div className="pt-2 border-t border-slate-200">
            <h4 className="text-sm font-bold text-slate-900 mb-2">
              Limitations and Responsible Use (Section 11)
            </h4>
            <ul className="space-y-1.5 text-xs text-slate-600 list-disc pl-4">
              <li>The data is synthetic and small; it may not represent real organizational behavior.</li>
              <li>Example IPs (192.0.2.x, 198.51.100.x, 203.0.113.x — RFC 5737 TEST-NET ranges) are not evidence of real malicious infrastructure.</li>
              <li>The prototype does not prove compromise, attribute an actor, or automatically respond.</li>
              <li>Business hours (06:00–22:00) and thresholds (5 failures, 3 failures before success, 3 accounts) are illustrative.</li>
              <li>Real deployment needs access controls, data protection, configurable rules, and organization-specific validation.</li>
            </ul>
          </div>
        </section>

        {/* Section 12: Final Submission Checklist */}
        <section className="lg:col-span-6 bg-white border border-slate-200 rounded-lg p-6">
          <h3 className="text-base font-bold text-slate-900">
            03. Final Submission Checklist (Section 12)
          </h3>
          <p className="text-xs text-slate-500 mt-0.5 mb-4">
            Verify each deliverable step before uploading to GitHub or Google Drive.
          </p>

          <div className="space-y-2.5">
            {SUBMISSION_CHECKLIST.map((item) => {
              const isChecked = !!checkedItems[item.id];
              return (
                <label
                  key={item.id}
                  className="flex items-start gap-3 p-3 border border-slate-200 rounded-md hover:bg-slate-50 cursor-pointer transition-colors"
                >
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={(e) =>
                      setCheckedItems((prev) => ({
                        ...prev,
                        [item.id]: e.target.checked,
                      }))
                    }
                    className="mt-0.5 h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-blue-600"
                  />
                  <div className="text-xs">
                    <div className="font-semibold text-slate-900">{item.label}</div>
                    <div className="font-mono text-slate-500 mt-0.5">{item.cmd}</div>
                  </div>
                </label>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
};

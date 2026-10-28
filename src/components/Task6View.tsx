import React, { useState } from 'react';
import {
  Check,
  Copy,
  Download,
  UserCheck,
  FileText,
} from 'lucide-react';
import {
  AnalystProfile,
  TASK6_QUESTIONS,
  buildTask6ReportMarkdown,
} from '../data/projectArtifacts';
import { AuthLogEvent } from '../utils/logAnalyzer';

interface Task6ViewProps {
  profile: AnalystProfile;
  onProfileChange: (next: AnalystProfile) => void;
  events: AuthLogEvent[];
  highlightedIp?: string;
}

const RECOMMENDED_ACTIONS = [
  {
    id: 'act-1',
    title: 'Check whether IPs belong to an approved VPN, NAT, campus, or corporate egress address.',
    detail: 'Compare 192.0.2.20, 198.51.100.45, and 203.0.113.88 against network asset inventory.',
  },
  {
    id: 'act-2',
    title: 'Review MFA results, session creation, device identifiers, and endpoint alerts if available.',
    detail: 'Inspect MFA factor completion and User-Agent/device telemetry for maya (09:03:42), sam (10:15:44), and jordan (23:48:19).',
  },
  {
    id: 'act-3',
    title: 'Ask the account owner to verify unexpected successful logins.',
    detail: 'Perform out-of-band verification with maya and jordan regarding their login sessions.',
  },
  {
    id: 'act-4',
    title: 'Preserve relevant logs and record the reason for follow-up.',
    detail: 'Retain immutable copy of data/auth_logs.csv and attach triage rationale to incident ticket.',
  },
  {
    id: 'act-5',
    title: 'Recommend rate limiting and suitable authentication protections where justified.',
    detail: 'Enforce progressive throttling after 5 failed attempts and mandatory MFA on off-hours logins.',
  },
];

export const Task6View: React.FC<Task6ViewProps> = ({
  profile,
  onProfileChange,
  events,
  highlightedIp,
}) => {
  const [selectedQuestionId, setSelectedQuestionId] = useState<string>(() => {
    if (highlightedIp === '198.51.100.45') return 'Q3';
    if (highlightedIp === '203.0.113.88') return 'Q4';
    return 'Q1';
  });
  const [checkedActions, setCheckedActions] = useState<Record<string, boolean>>({
    'act-1': true,
    'act-2': true,
    'act-3': true,
    'act-4': true,
    'act-5': true,
  });
  const [copiedReport, setCopiedReport] = useState(false);

  const reportMarkdown = buildTask6ReportMarkdown(profile);

  const handleCopyMarkdown = () => {
    navigator.clipboard?.writeText(reportMarkdown);
    setCopiedReport(true);
    setTimeout(() => setCopiedReport(false), 1800);
  };

  const handleDownloadMarkdown = () => {
    const blob = new Blob([reportMarkdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'task6_findings.md';
    a.click();
    URL.revokeObjectURL(url);
  };

  const activeQuestion =
    TASK6_QUESTIONS.find((q) => q.id === selectedQuestionId) ?? TASK6_QUESTIONS[0];

  const matchingEvents = events.filter((ev) => ev.source_ip === activeQuestion.relatedIp);

  return (
    <div className="space-y-8">
      {/* Personalization Banner (Section 12 Requirement) */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-200">
          <div>
            <div className="text-xs text-slate-500 mb-1">
              <span>Section 5 & Section 6</span>
              <span aria-hidden="true" className="mx-1.5">·</span>
              <span>Deliverable: reports/task6_findings.md</span>
              <span aria-hidden="true" className="mx-1.5">·</span>
              <span>Separate Fact from Hypothesis</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">
              Task 6 — Manual Authentication Log Investigation
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopyMarkdown}
              className="px-3.5 py-2 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              {copiedReport ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  Copied task6_findings.md
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Copy Report Markdown
                </>
              )}
            </button>
            <button
              type="button"
              onClick={handleDownloadMarkdown}
              className="px-3.5 py-2 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              Download task6_findings.md
            </button>
          </div>
        </div>

        {/* Analyst Personalization Inputs */}
        <div className="pt-4">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-700 mb-3">
            <UserCheck className="w-3.5 h-3.5 text-slate-500" />
            <span>Personalize Academic & Analyst Details (Updates Task 6 & Task 13 Reports):</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label htmlFor="analyst-name" className="block text-xs text-slate-600 mb-1">
                Analyst / Student Name
              </label>
              <input
                id="analyst-name"
                type="text"
                value={profile.analystName}
                onChange={(e) =>
                  onProfileChange({ ...profile, analystName: e.target.value })
                }
                className="w-full px-3 py-1.5 text-xs bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <div>
              <label htmlFor="student-id" className="block text-xs text-slate-600 mb-1">
                Candidate / Student ID
              </label>
              <input
                id="student-id"
                type="text"
                value={profile.studentId}
                onChange={(e) =>
                  onProfileChange({ ...profile, studentId: e.target.value })
                }
                className="w-full px-3 py-1.5 text-xs font-mono bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
            <div>
              <label htmlFor="course-cohort" className="block text-xs text-slate-600 mb-1">
                Assessment / Course Name
              </label>
              <input
                id="course-cohort"
                type="text"
                value={profile.courseCohort}
                onChange={(e) =>
                  onProfileChange({ ...profile, courseCohort: e.target.value })
                }
                className="w-full px-3 py-1.5 text-xs bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>
          </div>
        </div>
      </section>

      {/* Four Investigation Questions Interactive Explorer */}
      <section className="bg-white border border-slate-200 rounded-lg">
        <div className="p-6 border-b border-slate-200">
          <h3 className="text-base font-bold text-slate-900">
            01. Investigation Questions & Fact vs. Hypothesis Breakdown
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Goal: identify patterns and explain what should be checked next. Avoid declaring an attack without corroborating evidence.
          </p>

          <div
            role="tablist"
            aria-label="Task 6 Investigation Questions"
            className="flex flex-wrap gap-1.5 p-1.5 bg-slate-100 rounded-lg mt-4"
          >
            {TASK6_QUESTIONS.map((q) => {
              const isSelected = q.id === activeQuestion.id;
              return (
                <button
                  key={q.id}
                  role="tab"
                  aria-selected={isSelected}
                  type="button"
                  onClick={() => setSelectedQuestionId(q.id)}
                  className={`px-3 py-2 text-xs font-medium rounded-md transition-colors text-left whitespace-nowrap shrink-0 ${
                    isSelected
                      ? 'bg-white text-slate-900 shadow-xs border border-slate-200/80'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {q.id}: {q.question}
                </button>
              );
            })}
          </div>
        </div>

        {/* Active Question Analysis Panel */}
        <div className="p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-200">
            <div>
              <div className="text-xs font-mono text-slate-500">
                Question {activeQuestion.id} · Primary Source IP: {activeQuestion.relatedIp} · Accounts: {activeQuestion.relatedUsers.join(', ')}
              </div>
              <h4 className="text-base font-bold text-slate-900 mt-0.5">
                {activeQuestion.question}
              </h4>
            </div>
            <div className="text-xs text-slate-600 font-medium">
              {activeQuestion.evidenceSummary}
            </div>
          </div>

          {/* Fact / Hypothesis / Conclusion Grid (Section 6) */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
              <div className="text-xs font-semibold text-slate-900 mb-1">
                Fact (Directly Visible in Logs)
              </div>
              <p className="text-xs text-slate-700 leading-relaxed">
                {activeQuestion.fact}
              </p>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
              <div className="text-xs font-semibold text-slate-900 mb-1">
                Hypothesis (Possible Explanation)
              </div>
              <p className="text-xs text-slate-700 leading-relaxed">
                {activeQuestion.hypothesis}
              </p>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg">
              <div className="text-xs font-semibold text-slate-900 mb-1">
                Conclusion & Required Follow-Up
              </div>
              <p className="text-xs text-slate-700 leading-relaxed">
                {activeQuestion.conclusionGuidance}
              </p>
              <div className="mt-2 pt-2 border-t border-slate-200 text-xs font-medium text-blue-800">
                Next Check: {activeQuestion.followUp}
              </div>
            </div>
          </div>

          {/* Supporting Log Rows for Selected Question */}
          <div>
            <div className="text-xs font-semibold text-slate-700 mb-2">
              Corroborating Log Rows in data/auth_logs.csv for IP {activeQuestion.relatedIp} ({matchingEvents.length} rows):
            </div>
            <div className="overflow-x-auto border border-slate-200 rounded-md">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-slate-600 font-semibold">
                    <th className="py-2 px-3">Timestamp</th>
                    <th className="py-2 px-3">Username</th>
                    <th className="py-2 px-3">Source IP</th>
                    <th className="py-2 px-3">Event</th>
                    <th className="py-2 px-3">Result</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 font-mono tabular-nums">
                  {matchingEvents.map((ev, i) => (
                    <tr key={`${ev.timestamp}-${i}`} className="hover:bg-slate-50">
                      <td className="py-2 px-3 text-slate-900">{ev.timestamp}</td>
                      <td className="py-2 px-3 text-slate-900 font-medium">{ev.username}</td>
                      <td className="py-2 px-3 text-slate-700">{ev.source_ip}</td>
                      <td className="py-2 px-3 text-slate-600">{ev.event}</td>
                      <td className="py-2 px-3">
                        <span
                          className={
                            ev.result === 'failure'
                              ? 'text-amber-800 font-semibold'
                              : 'text-emerald-800 font-semibold'
                          }
                        >
                          {ev.result}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      {/* Evidence, Possible Interpretation & Follow-Up Matrix (Section 5 Table) */}
      <section className="bg-white border border-slate-200 rounded-lg">
        <div className="p-6 border-b border-slate-200">
          <h3 className="text-base font-bold text-slate-900">
            02. Complete Task 6 Evidence, Interpretation & Follow-Up Matrix
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Structured alignment with Section 5 of the Cybersecurity Assessment workflow guide.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-700 font-semibold">
                <th className="py-3 px-5">Evidence</th>
                <th className="py-3 px-5">Dataset Observation (data/auth_logs.csv)</th>
                <th className="py-3 px-5">Possible Interpretation</th>
                <th className="py-3 px-5">Follow-Up</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              <tr className="hover:bg-slate-50/70">
                <td className="py-3.5 px-5 font-semibold text-slate-900">
                  Repeated failures from one IP.
                </td>
                <td className="py-3.5 px-5 font-mono text-slate-700">
                  192.0.2.20 → 5 failures for maya (09:02:11–09:03:05)
                </td>
                <td className="py-3.5 px-5 text-slate-700">
                  Password mistakes or guessing activity.
                </td>
                <td className="py-3.5 px-5 text-slate-700">
                  Check account, MFA, source ownership, and rate limiting.
                </td>
              </tr>
              <tr className="hover:bg-slate-50/70">
                <td className="py-3.5 px-5 font-semibold text-slate-900">
                  Success after repeated failures.
                </td>
                <td className="py-3.5 px-5 font-mono text-slate-700">
                  192.0.2.20 → maya login,success at 09:03:42 after 5 failures
                </td>
                <td className="py-3.5 px-5 text-slate-700">
                  Could be legitimate recovery or successful guessing.
                </td>
                <td className="py-3.5 px-5 text-slate-700">
                  Verify with user; review session/device records.
                </td>
              </tr>
              <tr className="hover:bg-slate-50/70">
                <td className="py-3.5 px-5 font-semibold text-slate-900">
                  One IP touches several usernames.
                </td>
                <td className="py-3.5 px-5 font-mono text-slate-700">
                  198.51.100.45 → 4 users (alex, devon, priya, sam)
                </td>
                <td className="py-3.5 px-5 text-slate-700">
                  Could be enumeration or a shared VPN/NAT source.
                </td>
                <td className="py-3.5 px-5 text-slate-700">
                  Confirm network ownership and expected usage.
                </td>
              </tr>
              <tr className="hover:bg-slate-50/70">
                <td className="py-3.5 px-5 font-semibold text-slate-900">
                  Successful login at an unusual hour.
                </td>
                <td className="py-3.5 px-5 font-mono text-slate-700">
                  203.0.113.88 → jordan login,success at 23:48:19
                </td>
                <td className="py-3.5 px-5 text-slate-700">
                  May be unusual for that account.
                </td>
                <td className="py-3.5 px-5 text-slate-700">
                  Compare schedule and approved remote access.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* Recommended Actions Checklist & Deliverable Markdown Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <section className="lg:col-span-5 bg-white border border-slate-200 rounded-lg p-6">
          <h3 className="text-base font-bold text-slate-900">
            03. Recommended Investigation Actions (Section 6)
          </h3>
          <p className="text-xs text-slate-500 mt-0.5 mb-4">
            Interactive verification checklist for analyst follow-up workflow.
          </p>

          <div className="space-y-3">
            {RECOMMENDED_ACTIONS.map((item) => {
              const checked = !!checkedActions[item.id];
              return (
                <label
                  key={item.id}
                  className="flex items-start gap-3 p-3 border border-slate-200 rounded-md hover:bg-slate-50 cursor-pointer transition-colors"
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) =>
                      setCheckedActions((prev) => ({
                        ...prev,
                        [item.id]: e.target.checked,
                      }))
                    }
                    className="mt-0.5 h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-blue-600"
                  />
                  <div className="text-xs">
                    <div className="font-semibold text-slate-900">{item.title}</div>
                    <div className="text-slate-600 mt-0.5">{item.detail}</div>
                  </div>
                </label>
              );
            })}
          </div>
        </section>

        <section className="lg:col-span-7 bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-slate-600" />
              <div>
                <h3 className="text-sm font-bold text-slate-900 font-mono">
                  reports/task6_findings.md
                </h3>
                <p className="text-xs text-slate-500">
                  Personalized Task 6 Deliverable Markdown Preview
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleCopyMarkdown}
              className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              {copiedReport ? 'Copied!' : 'Copy Markdown'}
            </button>
          </div>
          <pre className="p-5 bg-slate-950 text-slate-100 font-mono text-xs overflow-x-auto max-h-[460px] whitespace-pre-wrap leading-relaxed">
            {reportMarkdown}
          </pre>
        </section>
      </div>
    </div>
  );
};

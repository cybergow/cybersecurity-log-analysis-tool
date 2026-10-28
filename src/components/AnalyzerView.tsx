import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  RotateCcw,
  Plus,
  AlertTriangle,
  CheckCircle2,
  FileCode2,
  Copy,
  Check,
  Trash2,
} from 'lucide-react';
import {
  AuthLogEvent,
  AnalysisReport,
  AnalyzerThresholds,
  DEFAULT_THRESHOLDS,
} from '../utils/logAnalyzer';
import {
  SCENARIO_PRESETS,
  DEFAULT_AUTH_LOGS_CSV,
} from '../data/projectArtifacts';

interface AnalyzerViewProps {
  csvText: string;
  onCsvChange: (nextCsv: string, presetId?: string) => void;
  activePresetId: string;
  events: AuthLogEvent[];
  report: AnalysisReport | null;
  validationError: string | null;
  thresholds: AnalyzerThresholds;
  onThresholdsChange: (next: AnalyzerThresholds) => void;
  onNavigateToTask6: (ip?: string) => void;
}

export const AnalyzerView: React.FC<AnalyzerViewProps> = ({
  csvText,
  onCsvChange,
  activePresetId,
  events,
  report,
  validationError,
  thresholds,
  onThresholdsChange,
  onNavigateToTask6,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [resultFilter, setResultFilter] = useState<'all' | 'failure' | 'success'>('all');
  const [hoursFilter, setHoursFilter] = useState<'all' | 'after_hours'>('all');
  const [selectedIpFilter, setSelectedIpFilter] = useState<string>('');
  const [showRawEditor, setShowRawEditor] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  // Add row form state
  const [newTimestamp, setNewTimestamp] = useState('2026-10-27T23:55:10');
  const [newUsername, setNewUsername] = useState('');
  const [newSourceIp, setNewSourceIp] = useState('');
  const [newResult, setNewResult] = useState<'failure' | 'success'>('failure');
  const [addRowError, setAddRowError] = useState<string | null>(null);

  const filteredEvents = useMemo(() => {
    const startSec = thresholds.normalStartHour * 3600;
    const endSec = thresholds.normalEndHour * 3600;

    return events.filter((ev) => {
      if (resultFilter !== 'all' && ev.result !== resultFilter) {
        return false;
      }
      if (selectedIpFilter && ev.source_ip !== selectedIpFilter) {
        return false;
      }
      if (hoursFilter === 'after_hours') {
        const [hh, mm, ss] = ev.hourMinute.split(':').map(Number);
        const sec = hh * 3600 + mm * 60 + ss;
        if (sec >= startSec && sec <= endSec) {
          return false;
        }
      }
      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        const matchUser = ev.username.toLowerCase().includes(q);
        const matchIp = ev.source_ip.toLowerCase().includes(q);
        const matchTs = ev.timestamp.toLowerCase().includes(q);
        if (!matchUser && !matchIp && !matchTs) {
          return false;
        }
      }
      return true;
    });
  }, [events, resultFilter, selectedIpFilter, hoursFilter, searchQuery, thresholds]);

  const handleAddEventRow = (e: React.FormEvent) => {
    e.preventDefault();
    setAddRowError(null);

    const trimmedTs = newTimestamp.trim();
    const trimmedUser = newUsername.trim().toLowerCase();
    const trimmedIp = newSourceIp.trim();

    if (!trimmedTs || !trimmedUser || !trimmedIp) {
      setAddRowError('Timestamp, username, and source IP are required to append a log event.');
      return;
    }
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(trimmedTs)) {
      setAddRowError('Timestamp must follow ISO-8601 format YYYY-MM-DDTHH:MM:SS.');
      return;
    }
    if (trimmedUser.includes(',') || trimmedIp.includes(',')) {
      setAddRowError('Username and Source IP cannot contain commas.');
      return;
    }

    const rowLine = `${trimmedTs},${trimmedUser},${trimmedIp},login,${newResult}`;
    const base = csvText.trim().length > 0
      ? csvText.trim()
      : 'timestamp,username,source_ip,event,result';
    onCsvChange(`${base}\n${rowLine}`, 'custom');
    setNewUsername('');
    setNewSourceIp('');
  };

  const handleCopyJson = () => {
    if (!report) return;
    navigator.clipboard?.writeText(JSON.stringify(report, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 1800);
  };

  // Map IP and timestamps to triggered rules for inline log annotation
  const eventAnnotations = useMemo(() => {
    const map = new Map<string, string[]>();
    if (!report) return map;

    for (const ev of events) {
      const notes: string[] = [];
      for (const alert of report.alerts) {
        if (alert.rule === 'Repeated failures' && alert.source_ip === ev.source_ip && ev.result === 'failure') {
          notes.push('Repeated failures (≥5)');
        }
        if (
          alert.rule === 'Success after failures' &&
          alert.source_ip === ev.source_ip &&
          alert.username === ev.username &&
          alert.success_timestamp === ev.timestamp
        ) {
          notes.push(`Success after ${alert.earlier_failure_count} failures`);
        }
        if (alert.rule === 'Multiple accounts' && alert.source_ip === ev.source_ip) {
          notes.push(`Multi-account IP (${alert.distinct_username_count} users)`);
        }
        if (
          alert.rule === 'After-hours success' &&
          alert.source_ip === ev.source_ip &&
          alert.username === ev.username &&
          alert.timestamp === ev.timestamp
        ) {
          notes.push('After-hours success');
        }
      }
      if (notes.length > 0) {
        map.set(`${ev.timestamp}|${ev.username}|${ev.source_ip}|${ev.result}`, notes);
      }
    }
    return map;
  }, [events, report]);

  return (
    <div className="space-y-8">
      {/* Section Header & Scenario Presets */}
      <section className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-5 border-b border-slate-200">
          <div>
            <div className="text-xs text-slate-500 mb-1">
              <span>Dataset & Rule Evaluation</span>
              <span aria-hidden="true" className="mx-1.5">·</span>
              <span className="font-mono">data/auth_logs.csv</span>
              <span aria-hidden="true" className="mx-1.5">·</span>
              <span>Python Standard Library Equivalent</span>
            </div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">
              Authentication Log Triage & Detection Engine
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setShowRawEditor((v) => !v)}
              className="px-3.5 py-2 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
            >
              <FileCode2 className="w-3.5 h-3.5" />
              {showRawEditor ? 'Hide Raw CSV Editor' : 'Edit Raw CSV'}
            </button>
            <button
              type="button"
              onClick={() => {
                setSelectedIpFilter('');
                setResultFilter('all');
                setHoursFilter('all');
                setSearchQuery('');
                onThresholdsChange(DEFAULT_THRESHOLDS);
                onCsvChange(DEFAULT_AUTH_LOGS_CSV, 'default');
              }}
              className="px-3.5 py-2 text-xs font-medium text-slate-700 border border-slate-200 hover:bg-slate-50 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset Default Dataset
            </button>
          </div>
        </div>

        {/* Scenario Test Presets (T1-T5 from Section 9) */}
        <div className="pt-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-600">
              Load Assessment Dataset or Test Plan Scenario (Section 9):
            </span>
            <span className="text-xs text-slate-500 font-mono tabular-nums">
              Active preset: {activePresetId.toUpperCase()}
            </span>
          </div>
          <div
            role="group"
            aria-label="Test Plan Scenario Presets"
            className="flex flex-wrap items-center gap-1.5 p-1.5 bg-slate-100 rounded-lg"
          >
            {SCENARIO_PRESETS.map((preset) => {
              const isActive = activePresetId === preset.id;
              return (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => {
                    setSelectedIpFilter('');
                    onCsvChange(preset.csv, preset.id);
                  }}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    isActive
                      ? 'bg-white text-slate-900 shadow-xs border border-slate-200/80'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {preset.shortTag}
                </button>
              );
            })}
            <button
              type="button"
              onClick={() => {
                setSelectedIpFilter('');
                onCsvChange('timestamp,username,source_ip,event,result', 'empty');
              }}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                activePresetId === 'empty'
                  ? 'bg-white text-slate-900 shadow-xs border border-slate-200/80'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Empty Header Only
            </button>
          </div>
        </div>

        {/* Raw CSV Editor Collapse */}
        {showRawEditor && (
          <div className="mt-4 pt-4 border-t border-slate-200">
            <label
              htmlFor="raw-csv-textarea"
              className="block text-xs font-semibold text-slate-700 mb-1.5"
            >
              Raw CSV Content (data/auth_logs.csv) — required columns: timestamp, username, source_ip, event, result
            </label>
            <textarea
              id="raw-csv-textarea"
              rows={8}
              value={csvText}
              onChange={(e) => onCsvChange(e.target.value, 'custom')}
              className="w-full font-mono text-xs p-3 bg-slate-900 text-slate-100 rounded-md border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>
        )}
      </section>

      {/* Input Validation Error State (Test T5) */}
      {validationError && (
        <section
          role="alert"
          aria-live="assertive"
          className="bg-red-50/80 border border-red-200 rounded-lg p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <div className="text-xs font-mono text-red-700">
                LogValidationError · Test Plan T5 Triggered
              </div>
              <h3 className="text-sm font-semibold text-red-900 mt-0.5">
                CSV Schema or Value Validation Failed
              </h3>
              <p className="text-xs text-red-800 mt-1 font-mono">
                {validationError}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onCsvChange(DEFAULT_AUTH_LOGS_CSV, 'default')}
            className="px-4 py-2 text-xs font-medium bg-red-700 text-white rounded-md hover:bg-red-800 transition-colors whitespace-nowrap shrink-0"
          >
            Restore Valid Dataset
          </button>
        </section>
      )}

      {/* KPI Metrics Strip */}
      {report && (
        <section
          aria-label="Log Analysis Summary Metrics"
          className="grid grid-cols-2 lg:grid-cols-5 bg-white border border-slate-200 rounded-lg divide-y sm:divide-y-0 sm:divide-x divide-slate-200"
        >
          <div className="p-5">
            <div className="text-xs text-slate-500">Total Login Events</div>
            <div className="text-2xl font-bold text-slate-900 font-mono tabular-nums mt-1">
              {report.summary.total_events}
            </div>
            <div className="text-xs text-slate-500 mt-1 font-mono tabular-nums">
              {report.summary.distinct_users} users · {report.summary.distinct_ips} IPs
            </div>
          </div>

          <div className="p-5">
            <div className="text-xs text-slate-500">Recorded Failures</div>
            <div className="text-2xl font-bold text-amber-700 font-mono tabular-nums mt-1">
              {report.summary.total_failures}
            </div>
            <div className="text-xs text-slate-500 mt-1">
              Threshold: ≥{thresholds.repeatedFailuresMin} per IP
            </div>
          </div>

          <div className="p-5">
            <div className="text-xs text-slate-500">Recorded Successes</div>
            <div className="text-2xl font-bold text-emerald-700 font-mono tabular-nums mt-1">
              {report.summary.total_successes}
            </div>
            <div className="text-xs text-slate-500 mt-1">
              Window: 06:00–22:00
            </div>
          </div>

          <div className="p-5">
            <div className="text-xs text-slate-500">Triage Alerts Fired</div>
            <div
              data-testid="total-alerts-metric"
              className={`text-2xl font-bold font-mono tabular-nums mt-1 ${
                report.summary.total_alerts > 0 ? 'text-red-600' : 'text-slate-900'
              }`}
            >
              {report.summary.total_alerts}
            </div>
            <div className="text-xs text-slate-500 mt-1">
              Across 4 defensive rules
            </div>
          </div>

          <div className="p-5 col-span-2 lg:col-span-1 flex flex-col justify-between">
            <div className="text-xs text-slate-500">Rule Breakdown</div>
            <div className="mt-1.5 space-y-1 text-xs font-mono tabular-nums text-slate-700">
              <div className="flex justify-between">
                <span>R1 Repeated Fail:</span>
                <span className="font-semibold">{report.summary.alerts_by_rule['Repeated failures']}</span>
              </div>
              <div className="flex justify-between">
                <span>R2 Success/Fail:</span>
                <span className="font-semibold">{report.summary.alerts_by_rule['Success after failures']}</span>
              </div>
              <div className="flex justify-between">
                <span>R3 Multi-Account:</span>
                <span className="font-semibold">{report.summary.alerts_by_rule['Multiple accounts']}</span>
              </div>
              <div className="flex justify-between">
                <span>R4 After-Hours:</span>
                <span className="font-semibold">{report.summary.alerts_by_rule['After-hours success']}</span>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Triggered Detection Rules & Live JSON Report Split */}
      {report && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left 7 cols: Triggered Triage Alerts */}
          <section className="lg:col-span-7 bg-white border border-slate-200 rounded-lg">
            <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  Triggered Triage Alerts ({report.alerts.length})
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Triage indicators require corroboration with MFA, session, device, and network context.
                </p>
              </div>
              {selectedIpFilter && (
                <button
                  type="button"
                  onClick={() => setSelectedIpFilter('')}
                  className="px-2.5 py-1 text-xs font-medium text-blue-700 hover:underline whitespace-nowrap"
                >
                  Clear IP filter ({selectedIpFilter})
                </button>
              )}
            </div>

            {report.alerts.length === 0 ? (
              <div className="p-8 text-center">
                <CheckCircle2 className="w-7 h-7 text-emerald-600 mx-auto mb-2" />
                <h4 className="text-sm font-semibold text-slate-900">
                  No Detection Thresholds Exceeded
                </h4>
                <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
                  None of the current events triggered Repeated Failures (≥5), Success After Failures (≥3), Multiple Accounts (≥3), or After-Hours Success (outside 06:00–22:00).
                </p>
              </div>
            ) : (
              <div className="divide-y divide-slate-200">
                {report.alerts.map((alert, idx) => {
                  const isIpFiltered = selectedIpFilter === alert.source_ip;
                  return (
                    <div key={`${alert.rule_id}-${idx}`} className="p-5 hover:bg-slate-50/70 transition-colors">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 text-xs min-w-0">
                          <span
                            className={`font-semibold whitespace-nowrap ${
                              alert.severity === 'high'
                                ? 'text-red-700'
                                : alert.severity === 'medium'
                                ? 'text-amber-700'
                                : 'text-blue-700'
                            }`}
                          >
                            {alert.severity === 'high'
                              ? 'High Priority'
                              : alert.severity === 'medium'
                              ? 'Medium Priority'
                              : 'Low Priority'}
                          </span>
                          <span aria-hidden="true" className="text-slate-300">·</span>
                          <span className="font-mono text-slate-600 truncate">{alert.rule_id}</span>
                          <span aria-hidden="true" className="text-slate-300">·</span>
                          <span className="font-mono text-slate-900 font-medium whitespace-nowrap">
                            IP {alert.source_ip}
                          </span>
                        </div>

                        <div className="flex items-center gap-2 shrink-0">
                          <button
                            type="button"
                            onClick={() =>
                              setSelectedIpFilter(isIpFiltered ? '' : alert.source_ip)
                            }
                            className={`px-2.5 py-1 text-xs font-medium rounded border transition-colors whitespace-nowrap shrink-0 ${
                              isIpFiltered
                                ? 'bg-slate-900 text-white border-slate-900'
                                : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-100'
                            }`}
                          >
                            {isIpFiltered ? 'Showing IP' : `Filter ${alert.source_ip}`}
                          </button>
                          <button
                            type="button"
                            onClick={() => onNavigateToTask6(alert.source_ip)}
                            className="px-2 py-1 text-xs font-medium text-blue-700 hover:text-blue-900 hover:underline whitespace-nowrap shrink-0"
                          >
                            Task 6 →
                          </button>
                        </div>
                      </div>

                      <h4 className="text-sm font-bold text-slate-900 mt-1.5">
                        {alert.rule} — {alert.meaning}
                      </h4>

                      <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                        <div>
                          <span className="text-slate-500">Observed Evidence: </span>
                          <span className="font-mono text-slate-800">
                            {alert.rule === 'Repeated failures' &&
                              `${alert.failure_count} failed logins (${alert.first_seen?.slice(11)} to ${alert.last_seen?.slice(11)}) for ${alert.usernames?.join(', ')}`}
                            {alert.rule === 'Success after failures' &&
                              `${alert.earlier_failure_count} earlier failures for '${alert.username}' before success at ${alert.success_timestamp?.slice(11)}`}
                            {alert.rule === 'Multiple accounts' &&
                              `${alert.distinct_username_count} distinct usernames (${alert.usernames?.join(', ')}) across ${alert.total_events} events`}
                            {alert.rule === 'After-hours success' &&
                              `Account '${alert.username}' succeeded at ${alert.timestamp} (outside ${alert.normal_window})`}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-500">Hypothesis: </span>
                          <span className="text-slate-800">{alert.possible_interpretation}</span>
                        </div>
                      </div>

                      <div className="mt-2 text-xs text-slate-600">
                        <span className="font-medium text-slate-700">Follow-up Action: </span>
                        {alert.recommended_followup}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </section>

          {/* Right 5 cols: Live JSON Report Output (reports/analysis_results.json) */}
          <section className="lg:col-span-5 bg-white border border-slate-200 rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900 font-mono">
                  reports/analysis_results.json
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Live serialized JSON output matching Python tool schema
                </p>
              </div>
              <button
                type="button"
                onClick={handleCopyJson}
                className="px-3 py-1.5 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                {copiedJson ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-600" />
                    Copied JSON
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Copy JSON
                  </>
                )}
              </button>
            </div>
            <pre
              aria-label="Generated JSON Report"
              className="p-4 bg-slate-950 text-slate-100 font-mono text-xs overflow-x-auto max-h-[420px] leading-relaxed"
            >
              {JSON.stringify(report, null, 2)}
            </pre>
          </section>
        </div>
      )}

      {/* Authentication Events Table & Interactive Event Appender */}
      <section className="bg-white border border-slate-200 rounded-lg">
        <div className="p-6 border-b border-slate-200 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Authentication Event Log Table ({filteredEvents.length} of {events.length} events)
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Sorted chronologically by ISO-8601 timestamp. Inspect individual rows or append synthetic test events below.
              </p>
            </div>

            {events.length > 0 && (
              <button
                type="button"
                onClick={() => onCsvChange('timestamp,username,source_ip,event,result', 'empty')}
                className="px-3 py-1.5 text-xs font-medium text-slate-600 hover:text-red-700 border border-slate-200 hover:border-red-200 rounded-md transition-colors flex items-center gap-1.5 self-start sm:self-auto whitespace-nowrap shrink-0"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Clear All Rows
              </button>
            )}
          </div>

          {/* Filter & Search Bar */}
          <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-md">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="search"
                aria-label="Search logs by username, source IP, or timestamp"
                placeholder="Search username (maya, jordan), IP (192.0.2.20), or time..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs border border-slate-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md">
                {(['all', 'failure', 'success'] as const).map((status) => (
                  <button
                    key={status}
                    type="button"
                    onClick={() => setResultFilter(status)}
                    className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                      resultFilter === status
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {status === 'all'
                      ? 'All Outcomes'
                      : status === 'failure'
                      ? 'Failures Only'
                      : 'Successes Only'}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1 p-1 bg-slate-100 rounded-md">
                <button
                  type="button"
                  onClick={() => setHoursFilter('all')}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    hoursFilter === 'all'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  All Hours
                </button>
                <button
                  type="button"
                  onClick={() => setHoursFilter('after_hours')}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    hoursFilter === 'after_hours'
                      ? 'bg-white text-slate-900 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  Outside 06:00–22:00
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Table Content or Empty State */}
        {filteredEvents.length === 0 ? (
          <div className="p-10 text-center">
            <Filter className="w-7 h-7 text-slate-400 mx-auto mb-2" />
            <h4 className="text-sm font-semibold text-slate-900">
              No Authentication Events Match Current View
            </h4>
            <p className="text-xs text-slate-500 max-w-md mx-auto mt-1 mb-4">
              {events.length === 0
                ? 'The dataset currently contains zero event rows. Load the default dataset or append a new login event below.'
                : 'No rows match your active search or outcome filters.'}
            </p>
            <button
              type="button"
              onClick={() => {
                setSearchQuery('');
                setResultFilter('all');
                setHoursFilter('all');
                setSelectedIpFilter('');
                if (events.length === 0) {
                  onCsvChange(DEFAULT_AUTH_LOGS_CSV, 'default');
                }
              }}
              className="px-4 py-2 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors"
            >
              {events.length === 0 ? 'Load Default Dataset (18 Events)' : 'Reset Active Filters'}
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50/80 text-xs font-semibold text-slate-600">
                  <th className="py-2.5 px-4 font-mono">#</th>
                  <th className="py-2.5 px-4">Timestamp (ISO-8601)</th>
                  <th className="py-2.5 px-4">Username</th>
                  <th className="py-2.5 px-4">Source IP</th>
                  <th className="py-2.5 px-4">Event</th>
                  <th className="py-2.5 px-4">Result</th>
                  <th className="py-2.5 px-4">Triage Rule Correlation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-xs">
                {filteredEvents.map((ev, idx) => {
                  const key = `${ev.timestamp}|${ev.username}|${ev.source_ip}|${ev.result}`;
                  const notes = eventAnnotations.get(key) ?? [];
                  return (
                    <tr
                      key={`${ev.rowNumber}-${idx}`}
                      className="hover:bg-slate-50 transition-colors h-10"
                    >
                      <td className="py-2 px-4 font-mono tabular-nums text-slate-400">
                        {idx + 1}
                      </td>
                      <td className="py-2 px-4 font-mono tabular-nums text-slate-900 whitespace-nowrap">
                        {ev.timestamp}
                      </td>
                      <td className="py-2 px-4 font-mono font-medium text-slate-900">
                        {ev.username}
                      </td>
                      <td className="py-2 px-4 font-mono tabular-nums text-slate-700">
                        <button
                          type="button"
                          onClick={() =>
                            setSelectedIpFilter(
                              selectedIpFilter === ev.source_ip ? '' : ev.source_ip
                            )
                          }
                          className="hover:text-blue-700 hover:underline text-left font-mono"
                          title="Click to filter by this Source IP"
                        >
                          {ev.source_ip}
                        </button>
                      </td>
                      <td className="py-2 px-4 font-mono text-slate-600">{ev.event}</td>
                      <td className="py-2 px-4 font-mono">
                        {ev.result === 'failure' ? (
                          <span className="text-amber-800 font-semibold">
                            failure
                          </span>
                        ) : (
                          <span className="text-emerald-800 font-semibold">
                            success
                          </span>
                        )}
                      </td>
                      <td className="py-2 px-4 text-slate-600">
                        {notes.length > 0 ? (
                          <span className="text-slate-900 font-medium">
                            {notes.join(' · ')}
                          </span>
                        ) : (
                          <span className="text-slate-400">Baseline / Within threshold</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Append Synthetic Log Event Form */}
        <div className="p-5 bg-slate-50 border-t border-slate-200 rounded-b-lg">
          <form onSubmit={handleAddEventRow} className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-700">
                Append Custom Event Row to CSV
              </span>
              <span className="text-xs text-slate-500">
                Test how adding a new failure or off-hours login changes the triage alerts
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
              <div>
                <label htmlFor="add-ts" className="block text-xs text-slate-600 mb-1">
                  Timestamp (ISO-8601)
                </label>
                <input
                  id="add-ts"
                  type="text"
                  value={newTimestamp}
                  onChange={(e) => setNewTimestamp(e.target.value)}
                  placeholder="2026-10-27T23:55:10"
                  className="w-full px-3 py-1.5 text-xs font-mono bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
              <div>
                <label htmlFor="add-user" className="block text-xs text-slate-600 mb-1">
                  Username
                </label>
                <input
                  id="add-user"
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. maya"
                  className="w-full px-3 py-1.5 text-xs font-mono bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
              <div>
                <label htmlFor="add-ip" className="block text-xs text-slate-600 mb-1">
                  Source IP
                </label>
                <input
                  id="add-ip"
                  type="text"
                  value={newSourceIp}
                  onChange={(e) => setNewSourceIp(e.target.value)}
                  placeholder="e.g. 192.0.2.20"
                  className="w-full px-3 py-1.5 text-xs font-mono bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                />
              </div>
              <div>
                <label htmlFor="add-result" className="block text-xs text-slate-600 mb-1">
                  Authentication Outcome
                </label>
                <select
                  id="add-result"
                  value={newResult}
                  onChange={(e) => setNewResult(e.target.value as 'failure' | 'success')}
                  className="w-full px-3 py-1.5 text-xs font-mono bg-white border border-slate-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-600"
                >
                  <option value="failure">failure</option>
                  <option value="success">success</option>
                </select>
              </div>
              <div className="flex items-end">
                <button
                  type="submit"
                  className="w-full px-4 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-colors flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0 h-[30px]"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Append Log Event
                </button>
              </div>
            </div>

            {addRowError && (
              <p role="alert" className="text-xs text-red-600 font-medium">
                {addRowError}
              </p>
            )}
          </form>
        </div>
      </section>
    </div>
  );
};

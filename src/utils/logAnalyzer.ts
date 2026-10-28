export interface AuthLogEvent {
  rowNumber: number;
  timestamp: string;
  parsedTimeMs: number;
  hourMinute: string; // HH:MM:SS
  username: string;
  source_ip: string;
  event: 'login';
  result: 'success' | 'failure';
}

export type RuleId =
  | 'R1_REPEATED_FAILURES'
  | 'R2_SUCCESS_AFTER_FAILURES'
  | 'R3_MULTIPLE_ACCOUNTS'
  | 'R4_AFTER_HOURS_SUCCESS';

export interface TriageAlert {
  rule_id: RuleId;
  rule: 'Repeated failures' | 'Success after failures' | 'Multiple accounts' | 'After-hours success';
  severity: 'high' | 'medium' | 'low';
  source_ip: string;
  username?: string;
  usernames?: string[];
  failure_count?: number;
  earlier_failure_count?: number;
  distinct_username_count?: number;
  total_events?: number;
  first_seen?: string;
  last_seen?: string;
  first_failure_timestamp?: string;
  success_timestamp?: string;
  timestamp?: string;
  normal_window?: string;
  meaning: string;
  possible_interpretation: string;
  recommended_followup: string;
}

export interface AnalysisSummary {
  total_events: number;
  total_failures: number;
  total_successes: number;
  distinct_users: number;
  distinct_ips: number;
  total_alerts: number;
  alerts_by_rule: {
    'Repeated failures': number;
    'Success after failures': number;
    'Multiple accounts': number;
    'After-hours success': number;
  };
}

export interface AnalysisReport {
  summary: AnalysisSummary;
  thresholds: {
    repeated_failures_min: number;
    success_after_failures_min: number;
    multiple_accounts_min: number;
    normal_hours_window: string;
  };
  alerts: TriageAlert[];
  disclaimer: string;
  input_file: string;
}

export interface AnalyzerThresholds {
  repeatedFailuresMin: number;
  successAfterFailuresMin: number;
  multipleAccountsMin: number;
  normalStartHour: number; // default 6 (06:00:00)
  normalEndHour: number;   // default 22 (22:00:00)
}

export const DEFAULT_THRESHOLDS: AnalyzerThresholds = {
  repeatedFailuresMin: 5,
  successAfterFailuresMin: 3,
  multipleAccountsMin: 3,
  normalStartHour: 6,
  normalEndHour: 22,
};

export const REQUIRED_CSV_COLUMNS = [
  'timestamp',
  'username',
  'source_ip',
  'event',
  'result',
] as const;

export class LogValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LogValidationError';
  }
}

const ISO_TIMESTAMP_REGEX =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$/;

export function parseIsoTimestamp(raw: string, rowNum: number): { ms: number; hourMinute: string; secondsSinceMidnight: number } {
  const trimmed = (raw || '').trim();
  if (!trimmed) {
    throw new LogValidationError(`Row ${rowNum}: Missing timestamp value.`);
  }
  const match = ISO_TIMESTAMP_REGEX.exec(trimmed);
  if (!match) {
    throw new LogValidationError(
      `Row ${rowNum}: Invalid ISO-8601 timestamp '${trimmed}'. Expected YYYY-MM-DDTHH:MM:SS.`
    );
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);

  if (
    month < 1 || month > 12 ||
    day < 1 || day > 31 ||
    hour < 0 || hour > 23 ||
    minute < 0 || minute > 59 ||
    second < 0 || second > 59
  ) {
    throw new LogValidationError(
      `Row ${rowNum}: Out-of-range calendar or clock value in timestamp '${trimmed}'.`
    );
  }

  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  const hourMinute = `${match[4]}:${match[5]}:${match[6]}`;
  const secondsSinceMidnight = hour * 3600 + minute * 60 + second;
  return { ms, hourMinute, secondsSinceMidnight };
}

export function parseAndValidateCsv(csvText: string): AuthLogEvent[] {
  const lines = csvText
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (lines.length === 0) {
    throw new LogValidationError('CSV file is empty or missing a header row.');
  }

  const headers = lines[0].split(',').map((h) => h.trim());
  const missingColumns = REQUIRED_CSV_COLUMNS.filter(
    (req) => !headers.includes(req)
  );
  if (missingColumns.length > 0) {
    throw new LogValidationError(
      `Missing required CSV column(s): ${missingColumns.join(', ')}`
    );
  }

  const colIndex: Record<string, number> = {};
  headers.forEach((h, idx) => {
    colIndex[h] = idx;
  });

  const events: Array<AuthLogEvent & { _sec: number }> = [];

  for (let i = 1; i < lines.length; i++) {
    const rowNum = i + 1;
    const cells = lines[i].split(',').map((c) => c.trim());

    for (const col of REQUIRED_CSV_COLUMNS) {
      const val = cells[colIndex[col]] ?? '';
      if (!val) {
        throw new LogValidationError(
          `Row ${rowNum}: Missing value for required column '${col}'.`
        );
      }
    }

    const rawTs = cells[colIndex['timestamp']];
    const rawUser = cells[colIndex['username']];
    const rawIp = cells[colIndex['source_ip']];
    const rawEvent = cells[colIndex['event']].toLowerCase();
    const rawResult = cells[colIndex['result']].toLowerCase();

    const { ms, hourMinute, secondsSinceMidnight } = parseIsoTimestamp(rawTs, rowNum);

    if (rawEvent !== 'login') {
      throw new LogValidationError(
        `Row ${rowNum}: Invalid event type '${cells[colIndex['event']]}'. Expected 'login'.`
      );
    }

    if (rawResult !== 'success' && rawResult !== 'failure') {
      throw new LogValidationError(
        `Row ${rowNum}: Invalid result '${cells[colIndex['result']]}'. Expected 'failure' or 'success'.`
      );
    }

    events.push({
      rowNumber: rowNum,
      timestamp: rawTs,
      parsedTimeMs: ms,
      hourMinute,
      username: rawUser.toLowerCase(),
      source_ip: rawIp,
      event: 'login',
      result: rawResult,
      _sec: secondsSinceMidnight,
    });
  }

  events.sort((a, b) => a.parsedTimeMs - b.parsedTimeMs);

  return events.map(({ _sec, ...rest }) => rest);
}

export function evaluateDetectionRules(
  events: AuthLogEvent[],
  thresholds: AnalyzerThresholds = DEFAULT_THRESHOLDS,
  inputFile = 'data/auth_logs.csv'
): AnalysisReport {
  const sorted = [...events].sort((a, b) => a.parsedTimeMs - b.parsedTimeMs);
  const alerts: TriageAlert[] = [];

  // Rule 1: Repeated failures (>= 5 failed login events from one IP)
  const failuresByIp = new Map<string, AuthLogEvent[]>();
  for (const ev of sorted) {
    if (ev.result === 'failure') {
      const list = failuresByIp.get(ev.source_ip) ?? [];
      list.push(ev);
      failuresByIp.set(ev.source_ip, list);
    }
  }

  const sortedFailedIps = Array.from(failuresByIp.keys()).sort();
  for (const ip of sortedFailedIps) {
    const failEvents = failuresByIp.get(ip)!;
    if (failEvents.length >= thresholds.repeatedFailuresMin) {
      const usernames = Array.from(new Set(failEvents.map((e) => e.username))).sort();
      alerts.push({
        rule_id: 'R1_REPEATED_FAILURES',
        rule: 'Repeated failures',
        severity: 'medium',
        source_ip: ip,
        usernames,
        failure_count: failEvents.length,
        first_seen: failEvents[0].timestamp,
        last_seen: failEvents[failEvents.length - 1].timestamp,
        meaning: 'Flag for investigation.',
        possible_interpretation: 'Password mistakes or guessing activity.',
        recommended_followup: 'Check account, MFA, source ownership, and rate limiting.',
      });
    }
  }

  // Rule 2: Success after failures (>= 3 earlier failures for the same username/IP before a success)
  const priorFailuresByPair = new Map<string, AuthLogEvent[]>();
  for (const ev of sorted) {
    const pairKey = `${ev.username}||${ev.source_ip}`;
    if (ev.result === 'failure') {
      const list = priorFailuresByPair.get(pairKey) ?? [];
      list.push(ev);
      priorFailuresByPair.set(pairKey, list);
    } else if (ev.result === 'success') {
      const earlierFailures = priorFailuresByPair.get(pairKey) ?? [];
      if (earlierFailures.length >= thresholds.successAfterFailuresMin) {
        alerts.push({
          rule_id: 'R2_SUCCESS_AFTER_FAILURES',
          rule: 'Success after failures',
          severity: 'high',
          username: ev.username,
          source_ip: ev.source_ip,
          earlier_failure_count: earlierFailures.length,
          first_failure_timestamp: earlierFailures[0].timestamp,
          success_timestamp: ev.timestamp,
          meaning: 'Verify account and session.',
          possible_interpretation: 'Could be legitimate recovery or successful guessing.',
          recommended_followup: 'Verify with user; review session/device records.',
        });
      }
      priorFailuresByPair.set(pairKey, []);
    }
  }

  // Rule 3: Multiple accounts (One IP has activity for at least 3 distinct usernames)
  const usersByIp = new Map<string, Set<string>>();
  const eventsByIp = new Map<string, AuthLogEvent[]>();
  for (const ev of sorted) {
    const uSet = usersByIp.get(ev.source_ip) ?? new Set<string>();
    uSet.add(ev.username);
    usersByIp.set(ev.source_ip, uSet);

    const eList = eventsByIp.get(ev.source_ip) ?? [];
    eList.push(ev);
    eventsByIp.set(ev.source_ip, eList);
  }

  const allIps = Array.from(usersByIp.keys()).sort();
  for (const ip of allIps) {
    const uSet = usersByIp.get(ip)!;
    if (uSet.size >= thresholds.multipleAccountsMin) {
      const ipEvents = eventsByIp.get(ip)!;
      alerts.push({
        rule_id: 'R3_MULTIPLE_ACCOUNTS',
        rule: 'Multiple accounts',
        severity: 'medium',
        source_ip: ip,
        distinct_username_count: uSet.size,
        usernames: Array.from(uSet).sort(),
        total_events: ipEvents.length,
        first_seen: ipEvents[0].timestamp,
        last_seen: ipEvents[ipEvents.length - 1].timestamp,
        meaning: 'Check shared-source behavior or enumeration.',
        possible_interpretation: 'Could be enumeration or a shared VPN/NAT source.',
        recommended_followup: 'Confirm network ownership and expected usage.',
      });
    }
  }

  // Rule 4: After-hours success (Successful login outside 06:00-22:00)
  const startSec = thresholds.normalStartHour * 3600;
  const endSec = thresholds.normalEndHour * 3600;
  const normalWindowLabel = `${String(thresholds.normalStartHour).padStart(2, '0')}:00-${String(thresholds.normalEndHour).padStart(2, '0')}:00`;

  for (const ev of sorted) {
    if (ev.result === 'success') {
      const [hh, mm, ss] = ev.hourMinute.split(':').map(Number);
      const evSec = hh * 3600 + mm * 60 + ss;
      if (evSec < startSec || evSec > endSec) {
        alerts.push({
          rule_id: 'R4_AFTER_HOURS_SUCCESS',
          rule: 'After-hours success',
          severity: 'low',
          username: ev.username,
          source_ip: ev.source_ip,
          timestamp: ev.timestamp,
          normal_window: normalWindowLabel,
          meaning: 'Compare with expected schedule.',
          possible_interpretation: 'May be unusual for that account.',
          recommended_followup: 'Compare schedule and approved remote access.',
        });
      }
    }
  }

  const totalFailures = sorted.filter((e) => e.result === 'failure').length;
  const totalSuccesses = sorted.filter((e) => e.result === 'success').length;
  const distinctUsers = new Set(sorted.map((e) => e.username)).size;
  const distinctIps = new Set(sorted.map((e) => e.source_ip)).size;

  const alertsByRule = {
    'Repeated failures': alerts.filter((a) => a.rule === 'Repeated failures').length,
    'Success after failures': alerts.filter((a) => a.rule === 'Success after failures').length,
    'Multiple accounts': alerts.filter((a) => a.rule === 'Multiple accounts').length,
    'After-hours success': alerts.filter((a) => a.rule === 'After-hours success').length,
  };

  return {
    summary: {
      total_events: sorted.length,
      total_failures: totalFailures,
      total_successes: totalSuccesses,
      distinct_users: distinctUsers,
      distinct_ips: distinctIps,
      total_alerts: alerts.length,
      alerts_by_rule: alertsByRule,
    },
    thresholds: {
      repeated_failures_min: thresholds.repeatedFailuresMin,
      success_after_failures_min: thresholds.successAfterFailuresMin,
      multiple_accounts_min: thresholds.multipleAccountsMin,
      normal_hours_window: normalWindowLabel,
    },
    alerts,
    disclaimer:
      'These are demonstration triage rules. Alerts do not prove compromise or attribute an actor; corroborate with MFA, session, device, and network context.',
    input_file: inputFile,
  };
}

export function formatConsoleSummary(report: AnalysisReport, outputPath = 'reports/analysis_results.json'): string {
  const s = report.summary;
  return [
    '=== Authentication Log Analyzer Summary ===',
    `Input file        : ${report.input_file}`,
    `Total events      : ${s.total_events} (Success: ${s.total_successes}, Failure: ${s.total_failures})`,
    `Distinct accounts : ${s.distinct_users}`,
    `Distinct IPs      : ${s.distinct_ips}`,
    `Total alerts      : ${s.total_alerts}`,
    `  - Repeated failures       : ${s.alerts_by_rule['Repeated failures']}`,
    `  - Success after failures  : ${s.alerts_by_rule['Success after failures']}`,
    `  - Multiple accounts       : ${s.alerts_by_rule['Multiple accounts']}`,
    `  - After-hours success     : ${s.alerts_by_rule['After-hours success']}`,
    `JSON report saved : ${outputPath}`,
  ].join('\n');
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseAndValidateCsv,
  evaluateDetectionRules,
  LogValidationError,
} from './logAnalyzer';
import { buildProjectZip } from './zipBuilder';

test('T1: Five failed events from one IP triggers Repeated-failed-logins alert', () => {
  const csv = [
    'timestamp,username,source_ip,event,result',
    '2026-10-27T09:02:11,maya,192.0.2.20,login,failure',
    '2026-10-27T09:02:24,maya,192.0.2.20,login,failure',
    '2026-10-27T09:02:38,maya,192.0.2.20,login,failure',
    '2026-10-27T09:02:51,maya,192.0.2.20,login,failure',
    '2026-10-27T09:03:05,maya,192.0.2.20,login,failure',
  ].join('\n');

  const events = parseAndValidateCsv(csv);
  const report = evaluateDetectionRules(events);
  const repeated = report.alerts.filter((a) => a.rule === 'Repeated failures');

  assert.equal(repeated.length, 1);
  assert.equal(repeated[0].source_ip, '192.0.2.20');
  assert.equal(repeated[0].failure_count, 5);
});

test('T2: Three failures then success for same user/IP triggers Success-after-failures alert', () => {
  const csv = [
    'timestamp,username,source_ip,event,result',
    '2026-10-27T09:02:11,maya,192.0.2.20,login,failure',
    '2026-10-27T09:02:25,maya,192.0.2.20,login,failure',
    '2026-10-27T09:02:40,maya,192.0.2.20,login,failure',
    '2026-10-27T09:03:01,maya,192.0.2.20,login,success',
  ].join('\n');

  const events = parseAndValidateCsv(csv);
  const report = evaluateDetectionRules(events);
  const saf = report.alerts.filter((a) => a.rule === 'Success after failures');

  assert.equal(saf.length, 1);
  assert.equal(saf[0].username, 'maya');
  assert.equal(saf[0].earlier_failure_count, 3);
});

test('T3: Only two failures from one IP produces no repeated-failure threshold alert', () => {
  const csv = [
    'timestamp,username,source_ip,event,result',
    '2026-10-27T11:20:10,liam,203.0.113.12,login,failure',
    '2026-10-27T11:20:28,liam,203.0.113.12,login,failure',
  ].join('\n');

  const events = parseAndValidateCsv(csv);
  const report = evaluateDetectionRules(events);
  assert.equal(report.alerts.length, 0);
});

test('T4: Successful login at 23:48 triggers After-hours triage alert', () => {
  const csv = [
    'timestamp,username,source_ip,event,result',
    '2026-10-27T23:48:19,jordan,203.0.113.88,login,success',
  ].join('\n');

  const events = parseAndValidateCsv(csv);
  const report = evaluateDetectionRules(events);
  const afterHours = report.alerts.filter((a) => a.rule === 'After-hours success');

  assert.equal(afterHours.length, 1);
  assert.equal(afterHours[0].username, 'jordan');
  assert.equal(afterHours[0].timestamp, '2026-10-27T23:48:19');
});

test('T5: Missing required CSV column or invalid timestamp throws LogValidationError', () => {
  const missingColCsv = [
    'timestamp,username,event,result',
    '2026-10-27T09:02:11,maya,login,failure',
  ].join('\n');
  assert.throws(() => parseAndValidateCsv(missingColCsv), LogValidationError);

  const invalidTsCsv = [
    'timestamp,username,source_ip,event,result',
    'not-a-timestamp,maya,192.0.2.20,login,failure',
  ].join('\n');
  assert.throws(() => parseAndValidateCsv(invalidTsCsv), LogValidationError);
});

test('ZIP builder produces valid PKZIP header and EOCD signature', () => {
  const zipBytes = buildProjectZip([
    { path: 'README.md', content: '# Test Project\n' },
    { path: 'data/auth_logs.csv', content: 'timestamp,username,source_ip,event,result\n' },
  ]);
  // Check local header PK\x03\x04
  assert.equal(zipBytes[0], 0x50);
  assert.equal(zipBytes[1], 0x4b);
  assert.equal(zipBytes[2], 0x03);
  assert.equal(zipBytes[3], 0x04);
  assert.ok(zipBytes.length > 100);
});

/**
 * Copyright 2026 Kedar Kulkarni
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { getAnalysis } from '../services/api';

const TABS = [
  { key: 'assets', label: 'Assets', cols: ['IP Address', 'Operating System', 'Confidence', 'MAC Address'] },
  { key: 'targets', label: 'Targets', cols: ['IP Address', 'Type'] },
  { key: 'tcp', label: 'TCP Connections', cols: ['Source', 'Destination', 'Service', 'Bytes Sent', 'Bytes Received', 'Duration (ms)'] },
  { key: 'other', label: 'Other Connections', cols: ['Source', 'Destination', 'Protocol', 'Service', 'Bytes Sent', 'Duration (ms)'] },
];

const EMPTY_FILTERS = { assets: { os: '' }, targets: { type: '' }, tcp: { service: '' }, other: { protocol: '', service: '' } };

function rawRows(tabKey, data) {
  switch (tabKey) {
    case 'assets':
      return data.assets || [];
    case 'targets':
      return data.targets || [];
    case 'tcp':
      return data.tcp_connections || [];
    case 'other':
      return data.other_connections || [];
    default:
      return [];
  }
}

function filterRows(tabKey, rows, filters) {
  switch (tabKey) {
    case 'assets':
      return filters.os ? rows.filter((r) => r.os_type === filters.os) : rows;
    case 'targets':
      return filters.type ? rows.filter((r) => r.label === filters.type) : rows;
    case 'tcp':
      return filters.service ? rows.filter((r) => r.service === filters.service) : rows;
    case 'other':
      return rows.filter(
        (r) => (!filters.protocol || r.protocol === filters.protocol) && (!filters.service || r.service === filters.service)
      );
    default:
      return rows;
  }
}

function uniqueValues(rows, key) {
  return Array.from(new Set((rows || []).map((r) => r[key]).filter(Boolean))).sort();
}

function renderRow(tabKey, item) {
  switch (tabKey) {
    case 'assets':
      return (
        <tr key={item.id}>
          <td>{item.ip_address}</td>
          <td>{item.os_type}</td>
          <td>{item.os_confidence.toFixed(1)}%</td>
          <td>{item.mac_address || '-'}</td>
        </tr>
      );
    case 'targets':
      return (
        <tr key={item.id}>
          <td>{item.ip_address}</td>
          <td>
            <span className={`tag ${item.label === 'public' ? 'tag-accent' : 'tag-neutral'}`}>
              {item.label}
            </span>
          </td>
        </tr>
      );
    case 'tcp':
      return (
        <tr key={item.id}>
          <td>{item.src_ip}:{item.src_port}</td>
          <td>{item.dst_ip}:{item.dst_port}</td>
          <td><span className="tag tag-neutral">{item.service}</span></td>
          <td>{item.bytes_sent.toLocaleString()}</td>
          <td>{item.bytes_received.toLocaleString()}</td>
          <td>{item.duration_ms.toLocaleString()}</td>
        </tr>
      );
    case 'other':
      return (
        <tr key={item.id}>
          <td>{item.src_ip}{item.src_port ? `:${item.src_port}` : ''}</td>
          <td>{item.dst_ip}{item.dst_port ? `:${item.dst_port}` : ''}</td>
          <td>{item.protocol}</td>
          <td><span className="tag tag-neutral">{item.service}</span></td>
          <td>{item.bytes_sent.toLocaleString()}</td>
          <td>{item.duration_ms.toLocaleString()}</td>
        </tr>
      );
    default:
      return null;
  }
}

function StatCard({ label, value }) {
  return (
    <div className="blueprint" style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 6 }}>
      <i className="corner tl"></i><i className="corner tr"></i><i className="corner bl"></i><i className="corner br"></i>
      <span style={{ fontSize: 11, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--color-accent)' }}>{label}</span>
      <span style={{ fontFamily: 'var(--font-heading)', fontWeight: 600, fontSize: 42, lineHeight: 1 }}>{value}</span>
    </div>
  );
}

function FilterSelect({ id, label, value, onChange, options }) {
  return (
    <div className="field" style={{ width: 200 }}>
      <label htmlFor={id}>{label}</label>
      <select id={id} className="input" value={value} onChange={onChange}>
        <option value="">All</option>
        {options.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
    </div>
  );
}

// Renders the currently-selected capture's analysis inline in the shell's
// main pane. Accepts `analysisId` from the shell; falls back to the route
// param so /analysis/:id still works as a direct/bookmarked link.
function AnalysisResults({ analysisId }) {
  const params = useParams();
  const id = analysisId || params.id;
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('assets');
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const tabRefs = useRef({});

  useEffect(() => {
    if (!id) {
      setData(null);
      setLoading(false);
      return undefined;
    }

    let cancelled = false;
    let timeoutId;
    setLoading(true);
    setError('');
    setData(null);
    setActiveTab('assets');
    setFilters(EMPTY_FILTERS);

    const fetchData = async () => {
      try {
        const result = await getAnalysis(id);
        if (cancelled) return;
        setData(result);
        setLoading(false);

        if (result.analysis && result.analysis.status !== 'completed' && result.analysis.status !== 'failed') {
          timeoutId = setTimeout(fetchData, 3000);
        }
      } catch (err) {
        if (cancelled) return;
        setError(err.response?.data?.error || 'Failed to load analysis');
        setLoading(false);
      }
    };

    fetchData();
    return () => {
      cancelled = true;
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, [id]);

  const filterOptions = useMemo(() => {
    if (!data) return { os: [], type: [], tcpService: [], otherProtocol: [], otherService: [] };
    return {
      os: uniqueValues(data.assets, 'os_type'),
      type: uniqueValues(data.targets, 'label'),
      tcpService: uniqueValues(data.tcp_connections, 'service'),
      otherProtocol: uniqueValues(data.other_connections, 'protocol'),
      otherService: uniqueValues(data.other_connections, 'service'),
    };
  }, [data]);

  const setTabFilter = (tabKey, field, value) => {
    setFilters((f) => ({ ...f, [tabKey]: { ...f[tabKey], [field]: value } }));
  };

  const focusTab = (index) => {
    const key = TABS[index].key;
    setActiveTab(key);
    tabRefs.current[key]?.focus();
  };

  const handleTabKeyDown = (e, index) => {
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      focusTab((index + 1) % TABS.length);
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      focusTab((index - 1 + TABS.length) % TABS.length);
    } else if (e.key === 'Home') {
      e.preventDefault();
      focusTab(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      focusTab(TABS.length - 1);
    }
  };

  if (!id) return null;

  if (loading && !data) {
    return (
      <div role="status" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, marginTop: 'var(--space-8)' }}>
        <div className="ps-spinner" aria-hidden="true"></div>
        <span className="text-muted">Loading analysis data…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div role="alert" style={{ fontSize: 13, color: 'var(--color-accent-800)', background: 'var(--color-accent-100)', padding: 'var(--space-3) var(--space-4)' }}>
        {error}
      </div>
    );
  }

  if (!data) return null;

  if (data.analysis && (data.analysis.status === 'pending' || data.analysis.status === 'processing')) {
    return (
      <div role="status" aria-live="polite" aria-atomic="true" className="blueprint" style={{ padding: 'var(--space-8)', textAlign: 'center' }}>
        <i className="corner tl"></i><i className="corner tr"></i><i className="corner bl"></i><i className="corner br"></i>
        <div className="ps-spinner" aria-hidden="true" style={{ margin: '0 auto var(--space-4)' }}></div>
        <h4 style={{ margin: '0 0 4px' }}>Analysis in progress…</h4>
        <p className="text-muted" style={{ margin: 0, fontSize: 13 }}>Status: {data.analysis.status}</p>
      </div>
    );
  }

  if (data.analysis && data.analysis.status === 'failed') {
    return (
      <div role="alert" style={{ fontSize: 13, color: 'var(--color-accent-800)', background: 'var(--color-accent-100)', padding: 'var(--space-3) var(--space-4)' }}>
        Analysis failed: {data.analysis.error_msg}
      </div>
    );
  }

  const activeDef = TABS.find((t) => t.key === activeTab);
  const activeFilters = filters[activeTab];
  const visibleRows = filterRows(activeTab, rawRows(activeTab, data), activeFilters);

  return (
    <div>
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        Analysis status: {data.analysis.status}
      </div>

      <h1 style={{ margin: '0 0 4px', fontSize: 36 }}>Analysis</h1>
      <p className="text-muted" style={{ fontSize: 13, margin: '0 0 var(--space-6)' }}>File: {data.analysis.filename}</p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 'var(--space-6)', marginBottom: 'var(--space-8)' }}>
        <StatCard label="Assets" value={data.asset_count} />
        <StatCard label="Targets" value={data.target_count} />
        <StatCard label="Public IPs" value={data.public_targets} />
        <StatCard label="Local IPs" value={data.local_targets} />
      </div>

      <div role="tablist" aria-label="Analysis result categories" style={{ display: 'flex', gap: 28, borderBottom: '1px solid var(--color-divider)', marginBottom: 'var(--space-4)' }}>
        {TABS.map((t, i) => {
          const active = t.key === activeTab;
          return (
            <button
              key={t.key}
              type="button"
              role="tab"
              id={`tab-${t.key}`}
              aria-selected={active}
              aria-controls={`tabpanel-${t.key}`}
              tabIndex={active ? 0 : -1}
              ref={(el) => { tabRefs.current[t.key] = el; }}
              className="ps-tab"
              onClick={() => setActiveTab(t.key)}
              onKeyDown={(e) => handleTabKeyDown(e, i)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                padding: '10px 0',
                fontFamily: 'var(--font-body)',
                fontSize: 13,
                letterSpacing: '0.05em',
                textTransform: 'uppercase',
                color: active ? 'var(--color-accent)' : 'color-mix(in srgb, var(--color-text) 60%, transparent)',
                borderBottom: `2px solid ${active ? 'var(--color-accent)' : 'transparent'}`,
                marginBottom: -1,
              }}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      <div role="tabpanel" id={`tabpanel-${activeTab}`} aria-labelledby={`tab-${activeTab}`}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>
          {activeTab === 'assets' && (
            <FilterSelect
              id="filter-assets-os"
              label="Operating System"
              value={activeFilters.os}
              onChange={(e) => setTabFilter('assets', 'os', e.target.value)}
              options={filterOptions.os}
            />
          )}
          {activeTab === 'targets' && (
            <FilterSelect
              id="filter-targets-type"
              label="Type"
              value={activeFilters.type}
              onChange={(e) => setTabFilter('targets', 'type', e.target.value)}
              options={filterOptions.type}
            />
          )}
          {activeTab === 'tcp' && (
            <FilterSelect
              id="filter-tcp-service"
              label="Service"
              value={activeFilters.service}
              onChange={(e) => setTabFilter('tcp', 'service', e.target.value)}
              options={filterOptions.tcpService}
            />
          )}
          {activeTab === 'other' && (
            <>
              <FilterSelect
                id="filter-other-protocol"
                label="Protocol"
                value={activeFilters.protocol}
                onChange={(e) => setTabFilter('other', 'protocol', e.target.value)}
                options={filterOptions.otherProtocol}
              />
              <FilterSelect
                id="filter-other-service"
                label="Service"
                value={activeFilters.service}
                onChange={(e) => setTabFilter('other', 'service', e.target.value)}
                options={filterOptions.otherService}
              />
            </>
          )}
        </div>

        <table className="table">
          <thead>
            <tr>
              {activeDef.cols.map((c) => <th key={c}>{c}</th>)}
            </tr>
          </thead>
          <tbody>
            {visibleRows.length === 0 ? (
              <tr>
                <td colSpan={activeDef.cols.length} className="text-muted">No matching rows.</td>
              </tr>
            ) : (
              visibleRows.map((item) => renderRow(activeTab, item))
            )}
          </tbody>
        </table>
      </div>
      <div style={{ height: 'var(--space-8)' }}></div>
    </div>
  );
}

export default AnalysisResults;

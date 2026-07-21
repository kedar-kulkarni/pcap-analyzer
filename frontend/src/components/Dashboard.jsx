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

import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { logout, getAnalyses, deleteAnalysis } from '../services/api';
import AnalysisResults from './AnalysisResults';
import Upload from './Upload';
import Dialog from './Dialog';
import {
  BrandIcon,
  SunIcon,
  MoonIcon,
  LogoutIcon,
  FileIcon,
  PlusIcon,
  PanelIcon,
  PanelExpandIcon,
  SettingsIcon,
  TrashIcon,
} from './icons';

const SIDEBAR_KEY = 'ps-sidebar-collapsed';

function readCollapsed() {
  try {
    return localStorage.getItem(SIDEBAR_KEY) === '1';
  } catch (e) {
    return false;
  }
}

function formatDate(value) {
  return new Date(value).toLocaleString();
}

function statusTagClass(status) {
  if (status === 'failed') return 'tag tag-error';
  return 'tag tag-outline';
}

// The app "shell": nav + collapsible capture list + the selected capture's
// results. Reads an optional :id route param once on mount so a bookmarked
// /analysis/:id link preselects a file, but selection afterwards is local
// state rather than continued route navigation.
function Dashboard({ dark, toggleDark, onLogout }) {
  const params = useParams();
  const navigate = useNavigate();

  const [analyses, setAnalyses] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [activeId, setActiveId] = useState(params.id || null);
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [deleteDialog, setDeleteDialog] = useState({ open: false, id: null, filename: '' });

  const fetchAnalyses = useCallback(async () => {
    try {
      const result = await getAnalyses();
      setAnalyses(result.analyses || []);
    } catch (err) {
      console.error('Failed to fetch analyses:', err);
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    fetchAnalyses();
  }, [fetchAnalyses]);

  useEffect(() => {
    const hasPending = analyses.some((a) => a.status === 'pending' || a.status === 'processing');
    if (!hasPending) return undefined;
    const t = setTimeout(fetchAnalyses, 4000);
    return () => clearTimeout(t);
  }, [analyses, fetchAnalyses]);

  useEffect(() => {
    try {
      localStorage.setItem(SIDEBAR_KEY, collapsed ? '1' : '0');
    } catch (e) {
      // localStorage unavailable — collapse state just won't persist.
    }
  }, [collapsed]);

  const handleLogout = async () => {
    try {
      await logout();
    } catch (err) {
      console.error('Logout failed:', err);
    } finally {
      onLogout();
      navigate('/login');
    }
  };

  const handleSelect = (id) => setActiveId(id);

  const handleUploadSuccess = (analysisId) => {
    setUploadOpen(false);
    fetchAnalyses();
    setActiveId(analysisId);
  };

  const handleDeleteRequest = (id, filename) => setDeleteDialog({ open: true, id, filename });
  const handleDeleteCancel = () => setDeleteDialog({ open: false, id: null, filename: '' });

  const handleDeleteConfirm = async () => {
    const { id } = deleteDialog;
    try {
      await deleteAnalysis(id);
      if (activeId === id) setActiveId(null);
      fetchAnalyses();
    } catch (err) {
      console.error('Failed to delete analysis:', err);
    } finally {
      setDeleteDialog({ open: false, id: null, filename: '' });
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <a href="#main-content" className="sr-only sr-only-focusable">
        Skip to main content
      </a>

      <div className="nav" style={{ borderBottom: '1px solid var(--color-divider)' }}>
        <span className="nav-brand" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="blueprint" style={{ width: 28, height: 28, display: 'grid', placeItems: 'center', color: 'var(--color-accent)' }}>
            <i className="corner tl"></i><i className="corner tr"></i><i className="corner bl"></i><i className="corner br"></i>
            <BrandIcon width={15} height={15} />
          </span>
          PCAP Analyzer
        </span>
        <span className="tag tag-neutral">{analyses.length} captures</span>
        <button
          type="button"
          className="btn btn-icon btn-secondary"
          onClick={toggleDark}
          title="Toggle theme"
          aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          {dark ? <MoonIcon /> : <SunIcon />}
        </button>
        <button type="button" className="btn btn-secondary" onClick={handleLogout}>
          <LogoutIcon />
          Sign out
        </button>
      </div>

      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>
        <aside
          style={{
            width: collapsed ? 56 : 260,
            flexShrink: 0,
            borderRight: '1px solid var(--color-divider)',
            display: 'flex',
            flexDirection: 'column',
            transition: 'width 0.12s ease-out',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: 'var(--space-3)', borderBottom: '1px solid var(--color-divider)' }}>
            {!collapsed && (
              <span style={{ fontSize: 11, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--color-accent)', marginRight: 'auto' }}>
                Captures
              </span>
            )}
            <button
              type="button"
              className="btn btn-icon btn-ghost"
              onClick={() => setCollapsed((c) => !c)}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              style={{ width: 28, height: 28 }}
            >
              {collapsed ? <PanelExpandIcon width={15} height={15} /> : <PanelIcon width={15} height={15} />}
            </button>
            {!collapsed && (
              <button
                type="button"
                className="btn btn-icon btn-ghost"
                onClick={() => setUploadOpen(true)}
                aria-label="Add PCAP file"
                title="Add PCAP file"
                style={{ width: 28, height: 28 }}
              >
                <PlusIcon width={15} height={15} />
              </button>
            )}
          </div>

          <nav aria-label="Captures" style={{ flex: 1, overflowY: 'auto' }}>
            {collapsed ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, padding: 'var(--space-2)' }}>
                <button
                  type="button"
                  className="btn btn-icon btn-ghost"
                  onClick={() => setUploadOpen(true)}
                  aria-label="Add PCAP file"
                  title="Add PCAP file"
                >
                  <PlusIcon width={15} height={15} />
                </button>
                {analyses.map((a) => {
                  const active = a.id === activeId;
                  return (
                    <button
                      key={a.id}
                      type="button"
                      className="btn btn-icon btn-secondary"
                      data-active={active}
                      onClick={() => handleSelect(a.id)}
                      title={a.filename}
                      aria-label={a.filename}
                      aria-current={active ? 'true' : undefined}
                      style={{
                        background: active ? 'var(--color-accent-100)' : undefined,
                        borderColor: active ? 'var(--color-accent)' : undefined,
                        color: active ? 'var(--color-accent-800)' : undefined,
                        fontFamily: 'var(--font-heading)',
                        fontWeight: 600,
                      }}
                    >
                      {a.filename.charAt(0).toUpperCase()}
                    </button>
                  );
                })}
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {loaded && analyses.length === 0 && (
                  <p className="text-muted" style={{ fontSize: 12.5, padding: 'var(--space-4) var(--space-3)' }}>
                    No captures yet. Upload a PCAP file to get started.
                  </p>
                )}
                {analyses.map((a) => {
                  const active = a.id === activeId;
                  return (
                    <div
                      key={a.id}
                      className="ps-file-btn"
                      data-active={active}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        padding: '8px var(--space-3)',
                        background: active ? 'var(--color-accent-100)' : undefined,
                      }}
                    >
                      <button
                        type="button"
                        onClick={() => handleSelect(a.id)}
                        aria-current={active ? 'true' : undefined}
                        style={{
                          all: 'unset',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 8,
                          flex: 1,
                          minWidth: 0,
                          cursor: 'pointer',
                          color: active ? 'var(--color-accent-800)' : 'var(--color-text)',
                        }}
                      >
                        <FileIcon width={15} height={15} style={{ flexShrink: 0 }} />
                        <span style={{ minWidth: 0, flex: 1 }}>
                          <span style={{ display: 'block', fontSize: 13, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {a.filename}
                          </span>
                          <span className="text-muted" style={{ display: 'block', fontSize: 11 }}>
                            {formatDate(a.created_at)}
                          </span>
                        </span>
                      </button>
                      {a.status !== 'completed' && (
                        <span className={statusTagClass(a.status)}>{a.status}</span>
                      )}
                      <button
                        type="button"
                        className="btn btn-icon btn-ghost"
                        onClick={() => handleDeleteRequest(a.id, a.filename)}
                        aria-label={`Delete analysis for ${a.filename}`}
                        title="Delete"
                        style={{ width: 26, height: 26, flexShrink: 0 }}
                      >
                        <TrashIcon width={14} height={14} />
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </nav>

          <div style={{ borderTop: '1px solid var(--color-divider)' }}>
            <button
              type="button"
              className="ps-file-btn"
              onClick={() => setSettingsOpen(true)}
              style={{
                all: 'unset',
                boxSizing: 'border-box',
                display: 'flex',
                alignItems: 'center',
                justifyContent: collapsed ? 'center' : 'flex-start',
                gap: 8,
                width: '100%',
                padding: collapsed ? '10px' : '10px var(--space-3)',
                cursor: 'pointer',
                fontSize: 13,
              }}
            >
              <SettingsIcon width={15} height={15} />
              {!collapsed && 'Settings'}
            </button>
          </div>
        </aside>

        <main id="main-content" style={{ flex: 1, minWidth: 0, padding: 'var(--space-8)', overflowY: 'auto' }}>
          {activeId ? (
            <AnalysisResults analysisId={activeId} />
          ) : (
            <div className="blueprint" style={{ padding: 'var(--space-8)', textAlign: 'center', maxWidth: 420, margin: '10vh auto 0' }}>
              <i className="corner tl"></i><i className="corner tr"></i><i className="corner bl"></i><i className="corner br"></i>
              <h4 style={{ margin: '0 0 4px' }}>No capture selected</h4>
              <p className="text-muted" style={{ fontSize: 13, margin: '0 0 var(--space-4)' }}>
                Upload a PCAP file to get started, or pick one from the sidebar.
              </p>
              <button type="button" className="btn btn-primary" onClick={() => setUploadOpen(true)}>
                <PlusIcon />
                Add PCAP file
              </button>
            </div>
          )}
        </main>
      </div>

      {uploadOpen && (
        <Dialog labelledBy="upload-dialog-title" onClose={() => setUploadOpen(false)}>
          <Upload onUploadSuccess={handleUploadSuccess} onCancel={() => setUploadOpen(false)} />
        </Dialog>
      )}

      {settingsOpen && (
        <Dialog labelledBy="settings-dialog-title" onClose={() => setSettingsOpen(false)} width={360}>
          <div className="dialog-title" id="settings-dialog-title">Settings</div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 0' }}>
            <span>
              <span style={{ display: 'block', fontFamily: 'var(--font-heading)', fontWeight: 600, fontSize: 15 }}>Appearance</span>
              <span className="text-muted" style={{ fontSize: 12 }}>Light / dark theme</span>
            </span>
            <button
              type="button"
              className="btn btn-icon btn-secondary"
              onClick={toggleDark}
              aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
            >
              {dark ? <MoonIcon /> : <SunIcon />}
            </button>
          </div>
          <div className="dialog-actions">
            <button type="button" className="btn btn-primary" onClick={() => setSettingsOpen(false)}>Done</button>
          </div>
        </Dialog>
      )}

      {deleteDialog.open && (
        <Dialog labelledBy="delete-dialog-title" onClose={handleDeleteCancel} width={380}>
          <div className="dialog-title" id="delete-dialog-title">Delete capture</div>
          <p className="text-muted" style={{ margin: 0, fontSize: 13 }}>
            Are you sure you want to delete the analysis for &quot;{deleteDialog.filename}&quot;? This action cannot be undone.
          </p>
          <div className="dialog-actions">
            <button type="button" className="btn btn-secondary" onClick={handleDeleteCancel}>Cancel</button>
            <button type="button" className="btn btn-primary" onClick={handleDeleteConfirm}>Delete</button>
          </div>
        </Dialog>
      )}
    </div>
  );
}

export default Dashboard;

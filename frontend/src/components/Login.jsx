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

import React, { useState } from 'react';
import { login } from '../services/api';
import { BrandIcon, SunIcon, MoonIcon } from './icons';

function Login({ onLoginSuccess, dark, toggleDark }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(username, password);
      onLoginSuccess();
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'grid',
        placeItems: 'center',
        padding: 'var(--space-6)',
        background: 'var(--color-bg)',
        position: 'relative',
      }}
    >
      <button
        type="button"
        className="btn btn-icon btn-secondary"
        onClick={toggleDark}
        title="Toggle theme"
        aria-label={dark ? 'Switch to light theme' : 'Switch to dark theme'}
        style={{ position: 'absolute', top: 'var(--space-6)', right: 'var(--space-6)', width: 36, height: 36 }}
      >
        {dark ? <MoonIcon /> : <SunIcon />}
      </button>

      <div style={{ width: 380, maxWidth: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'center', marginBottom: 'var(--space-6)' }}>
          <span className="blueprint" style={{ width: 34, height: 34, display: 'grid', placeItems: 'center', color: 'var(--color-accent)' }}>
            <i className="corner tl"></i><i className="corner tr"></i><i className="corner bl"></i><i className="corner br"></i>
            <BrandIcon width={18} height={18} />
          </span>
          <span style={{ fontFamily: 'var(--font-heading)', fontWeight: 600, fontSize: 22, letterSpacing: '-0.01em' }}>
            PCAP Analyzer
          </span>
        </div>

        <form
          onSubmit={handleSubmit}
          className="blueprint"
          style={{ padding: 'var(--space-6)', background: 'var(--color-surface)', display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}
        >
          <i className="corner tl"></i><i className="corner tr"></i><i className="corner bl"></i><i className="corner br"></i>
          <div>
            <h4 style={{ margin: '0 0 4px' }}>Sign in</h4>
            <p className="text-muted" style={{ margin: 0, fontSize: 13 }}>Network capture analysis console</p>
          </div>

          <div className="field">
            <label htmlFor="ps-user">Username</label>
            <input
              className="input"
              id="ps-user"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="demo"
              required
              autoFocus
              aria-describedby={error ? 'login-error' : undefined}
            />
          </div>
          <div className="field">
            <label htmlFor="ps-pass">Password</label>
            <input
              className="input"
              id="ps-pass"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="demo"
              required
              aria-describedby={error ? 'login-error' : undefined}
            />
          </div>

          {error && (
            <div id="login-error" role="alert" style={{ fontSize: 12, color: 'var(--color-accent-800)', background: 'var(--color-accent-100)', padding: '6px 10px' }}>
              {error}
            </div>
          )}

          <button type="submit" className="btn btn-primary btn-block blueprint" style={{ marginTop: 0 }} disabled={loading}>
            <i className="corner tl"></i><i className="corner tr"></i><i className="corner bl"></i><i className="corner br"></i>
            <span aria-live="polite" aria-atomic="true">
              {loading ? 'Signing in…' : 'Sign in'}
            </span>
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, borderTop: '1px solid var(--color-divider)', paddingTop: 'var(--space-3)' }}>
            <span className="tag tag-outline">DEMO</span>
            <span className="text-muted">
              Username <strong style={{ color: 'var(--color-text)' }}>demo</strong> · Password{' '}
              <strong style={{ color: 'var(--color-text)' }}>demo</strong>
            </span>
          </div>
        </form>
      </div>
    </div>
  );
}

export default Login;

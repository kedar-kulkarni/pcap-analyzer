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
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import { checkSession } from './services/api';

const THEME_KEY = 'ps-theme';

function readDark() {
  try {
    return localStorage.getItem(THEME_KEY) === 'dark';
  } catch (e) {
    return false;
  }
}

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [dark, setDark] = useState(readDark);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    try {
      localStorage.setItem(THEME_KEY, dark ? 'dark' : 'light');
    } catch (e) {
      // localStorage unavailable (e.g. private browsing) — theme just won't persist.
    }
  }, [dark]);

  const toggleDark = useCallback(() => setDark((d) => !d), []);

  useEffect(() => {
    const verifySession = async () => {
      try {
        const result = await checkSession();
        setAuthenticated(result.authenticated);
      } catch (err) {
        setAuthenticated(false);
      } finally {
        setLoading(false);
      }
    };

    verifySession();
  }, []);

  const handleLoginSuccess = () => {
    setAuthenticated(true);
  };

  const handleLogout = () => {
    setAuthenticated(false);
  };

  if (loading) {
    return (
      <div role="status" className="sr-only">
        Loading application…
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        <Route
          path="/login"
          element={
            authenticated ? (
              <Navigate to="/" replace />
            ) : (
              <Login onLoginSuccess={handleLoginSuccess} dark={dark} toggleDark={toggleDark} />
            )
          }
        />
        <Route
          path="/"
          element={
            authenticated ? (
              <Dashboard dark={dark} toggleDark={toggleDark} onLogout={handleLogout} />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
        <Route
          path="/analysis/:id"
          element={
            authenticated ? (
              <Dashboard dark={dark} toggleDark={toggleDark} onLogout={handleLogout} />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />
      </Routes>
    </Router>
  );
}

export default App;

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
import { uploadPCAP } from '../services/api';
import { CloseIcon, UploadCloudIcon } from './icons';

// Body of the "Add PCAP file" dialog: a drag-and-drop zone that uploads
// as soon as a valid file is chosen (matching the design's instant-add
// feel), with a real progress bar and error recovery since the actual
// upload is asynchronous and can fail — unlike the design mock's synthetic
// data generator.
function Upload({ onUploadSuccess, onCancel }) {
  const [error, setError] = useState('');
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState('');

  const isValidExt = (name) => {
    const ext = name.split('.').pop().toLowerCase();
    return ext === 'pcap' || ext === 'pcapng';
  };

  const startUpload = async (file) => {
    if (!file) return;
    if (!isValidExt(file.name)) {
      setError('Invalid file type. Please select a .pcap or .pcapng file.');
      return;
    }

    setError('');
    setFileName(file.name);
    setUploading(true);
    setProgress(0);

    try {
      const result = await uploadPCAP(file, (progressEvent) => {
        const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        setProgress(percentCompleted);
      });
      onUploadSuccess(result.analysis_id);
    } catch (err) {
      setError(err.response?.data?.error || 'Upload failed');
      setUploading(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (uploading) return;
    startUpload(e.dataTransfer?.files?.[0]);
  };
  const handleDragOver = (e) => {
    e.preventDefault();
    if (!dragOver) setDragOver(true);
  };
  const handleDragLeave = (e) => {
    e.preventDefault();
    setDragOver(false);
  };
  const handlePick = (e) => {
    startUpload(e.target.files?.[0]);
  };

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'flex-start' }}>
        <div style={{ flex: 1 }}>
          <div className="dialog-title" id="upload-dialog-title">Add PCAP file</div>
          <p className="text-muted" style={{ margin: '2px 0 0', fontSize: 13 }}>Upload a capture to analyze</p>
        </div>
        <button
          type="button"
          className="btn btn-icon btn-ghost"
          onClick={onCancel}
          title="Close"
          aria-label="Close dialog"
          style={{ borderColor: 'transparent' }}
          disabled={uploading}
        >
          <CloseIcon width={18} height={18} />
        </button>
      </div>

      {error && (
        <div
          role="alert"
          style={{ fontSize: 12, color: 'var(--color-accent-800)', background: 'var(--color-accent-100)', padding: '6px 10px' }}
        >
          {error}
        </div>
      )}

      {uploading ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10, padding: 'var(--space-8) var(--space-6)' }}>
          <div className="ps-spinner" aria-hidden="true"></div>
          <span aria-hidden="true" style={{ fontFamily: 'var(--font-heading)', fontWeight: 600, fontSize: 15 }}>
            Uploading {fileName}…
          </span>
          <div
            role="progressbar"
            aria-label="File upload progress"
            aria-valuenow={progress}
            aria-valuemin={0}
            aria-valuemax={100}
            className="progress-track"
          >
            <div className="progress-fill" style={{ width: `${progress}%` }}></div>
          </div>
          <span aria-hidden="true" className="text-muted" style={{ fontSize: 12.5 }}>{progress}%</span>
          <div className="sr-only" aria-live="assertive" aria-atomic="true">
            Uploading {fileName}, {progress}% complete
          </div>
        </div>
      ) : (
        <label
          className="ps-drop"
          data-drag={dragOver}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: 10,
            padding: 'var(--space-8) var(--space-6)',
            border: '1.5px dashed var(--color-divider)',
            cursor: 'pointer',
            textAlign: 'center',
            transition: 'background 0.1s, border-color 0.1s',
          }}
        >
          <span style={{ color: 'var(--color-accent)' }}>
            <UploadCloudIcon width={34} height={34} />
          </span>
          <span style={{ fontFamily: 'var(--font-heading)', fontWeight: 600, fontSize: 16 }}>
            Drag &amp; drop a .pcap file
          </span>
          <span className="text-muted" style={{ fontSize: 12.5 }}>
            or <span style={{ color: 'var(--color-accent)' }}>browse</span> to choose · .pcap, .pcapng
          </span>
          <input
            type="file"
            accept=".pcap,.pcapng"
            onChange={handlePick}
            style={{ display: 'none' }}
            aria-label="Choose a PCAP file to upload"
          />
        </label>
      )}

      <div className="dialog-actions">
        <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={uploading}>
          Cancel
        </button>
      </div>
    </>
  );
}

export default Upload;

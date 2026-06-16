import { useState, useEffect, useMemo } from 'react';
import ResearchDashboard from './ResearchDashboard';
import './App.css';

type ScanResult = {
  id: string | number;
  scan_type: string;
  tool: string;
  result_path: string;
  target?: string;
  status: string;
  error_message?: string;
  created_at: string;
};

type Finding = {
  title?: string;
  issue_text?: string;
  severity?: string;
  issue_severity?: string;
  confidence?: string;
  filename?: string;
  file?: string;
  url?: string;
  endpoint?: string;
  line_number?: number;
  cwe?: string;
  cweid?: string;
  test_id?: string;
  description?: string;
  solution?: string;
  alert?: string;
  owasp_category?: string;
};

type SortDir = 'asc' | 'desc';
type SortField = keyof ScanResult | '';

type Page = 'scanner' | 'research';

const Icons = {
  Shield: ({ size = 24 }: { size?: number }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  ),
  Upload: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
    </svg>
  ),
  Play: () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  ),
  Refresh: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
    </svg>
  ),
  Code: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
    </svg>
  ),
  Globe: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  ),
  Merge: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M6 21V9a9 9 0 0 0 9 9"/>
    </svg>
  ),
  Download: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
    </svg>
  ),
  Chart: () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>
    </svg>
  ),
  Alert: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  ),
  Check: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  ),
  File: () => (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/>
    </svg>
  ),
};

function severityClass(sev?: string): string {
  const s = (sev || '').toUpperCase();
  if (s === 'CRITICAL') return 'sev-critical';
  if (s === 'HIGH')     return 'sev-high';
  if (s === 'MEDIUM')   return 'sev-medium';
  if (s === 'LOW')      return 'sev-low';
  return 'sev-info';
}

function FindingCard({ f, index }: { f: Finding; index: number }) {
  const sev   = f.severity || f.issue_severity || 'INFO';
  const title = findingLabel(f);
  const loc   = findingLocation(f);
  const line  = f.line_number ? `:${f.line_number}` : '';
  const cwe   = f.cwe || f.cweid || '';
  const desc  = f.description || '';
  const sol   = f.solution || '';

  return (
    <div className={`finding-card ${severityClass(sev)}`} style={{ animationDelay: `${index * 60}ms` }}>
      <div className="finding-header">
        <span className={`sev-badge ${severityClass(sev)}`}>{sev.toUpperCase()}</span>
        {f.test_id && <span className="finding-id">{f.test_id}</span>}
        {f.owasp_category && <span className="finding-cwe">{f.owasp_category}</span>}
        {cwe && <span className="finding-cwe">{cwe}</span>}
      </div>
      <p className="finding-title">{title}</p>
      {desc && desc !== title && <p className="finding-desc">{desc}</p>}
      {sol && <p className="finding-desc" style={{ color: 'var(--success)', fontSize: '0.78rem' }}>
        ✓ {sol}
      </p>}
      {loc && (
        <div className="finding-loc">
          <Icons.File /> <code>{loc}{line}</code>
        </div>
      )}
    </div>
  );
}

function parseFindings(result: Record<string, unknown>): Finding[] {
  // DAST scanner devuelve 'vulnerabilities' (campo principal)
  if (Array.isArray(result.vulnerabilities)) return result.vulnerabilities as Finding[];

  // HYBRID / resultado genérico con 'findings'
  if (Array.isArray(result.findings)) return result.findings as Finding[];

  // Bandit: 'results' en el nivel raíz (formato directo)
  if (Array.isArray(result.results)) return result.results as Finding[];

  // Bandit anidado dentro de la respuesta del backend
  const bandit = result.bandit_results as Record<string, unknown> | undefined;
  if (bandit && Array.isArray(bandit.results)) return bandit.results as Finding[];

  // Semgrep anidado
  const semgrep = result.semgrep_results as Record<string, unknown> | undefined;
  if (semgrep && Array.isArray(semgrep.results)) return semgrep.results as Finding[];

  return [];
}

function findingLabel(f: Finding): string {
  return f.alert || f.title || f.issue_text || f.description || 'Hallazgo de seguridad';
}

function findingLocation(f: Finding): string {
  return f.url || f.filename || f.file || f.endpoint || '';
}

function ScanSummaryBar({ result }: { result: Record<string, unknown> }) {
  const findings = parseFindings(result);
  if (findings.length === 0) return null;

  const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  findings.forEach(f => {
    const s = (f.severity || f.issue_severity || 'INFO').toUpperCase();
    counts[s in counts ? s : 'INFO']++;
  });

  return (
    <div className="summary-bar">
      <span className="summary-total">{findings.length} hallazgos</span>
      {(Object.entries(counts) as [string, number][])
        .filter(([, c]) => c > 0)
        .map(([sev, c]) => (
          <span key={sev} className={`sev-pill ${severityClass(sev)}`}>
            {c} {sev}
          </span>
        ))}
    </div>
  );
}

function App() {
  const [activePage, setActivePage] = useState<Page>('scanner');
  const [selectedFile, setSelectedFile]   = useState<File | null>(null);
  const [uploadMessage, setUploadMessage] = useState('');
  const [uploadError, setUploadError]     = useState('');
  const [scanType, setScanType]           = useState<'sast' | 'dast' | 'hybrid'>('sast');
  const [tool, setTool]                   = useState<'bandit' | 'semgrep'>('bandit');
  const [targetPath, setTargetPath]       = useState('');
  const [targetUrl, setTargetUrl]         = useState('');
  const [scanResult, setScanResult]       = useState<Record<string, unknown> | null>(null);
  const [scanError, setScanError]         = useState('');
  const [isLoading, setIsLoading]         = useState(false);
  const [results, setResults]             = useState<ScanResult[]>([]);
  const [downloadError, setDownloadError] = useState('');
  const [downloadMessage, setDownloadMessage] = useState('');
  const [selectedSastId, setSelectedSastId]   = useState('');
  const [selectedDastId, setSelectedDastId]   = useState('');
  const [showRaw, setShowRaw]             = useState(false);

  // DataTable state
  const [dtSearch,  setDtSearch]  = useState('');
  const [dtSort,    setDtSort]    = useState<SortField>('created_at');
  const [dtDir,     setDtDir]     = useState<SortDir>('desc');
  const [dtPage,    setDtPage]    = useState(1);
  const DT_PAGE_SIZE = 10;

  const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  useEffect(() => { fetchResults(); }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) {
      const f = e.target.files[0];
      if (f.size > 10 * 1024 * 1024) { setUploadError('Archivo demasiado grande (máx 10 MB)'); return; }
      setSelectedFile(f);
      setUploadError('');
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setIsLoading(true);
    setUploadError('');
    setUploadMessage('');
    const fd = new FormData();
    fd.append('file', selectedFile);
    try {
      const res = await fetch(`${API}/upload/`, { method: 'POST', body: fd });
      if (!res.ok) throw new Error((await res.json()).detail || 'Error subiendo');
      const data = await res.json();
      setUploadMessage('Archivo subido');
      setTargetPath(data.file_path);
    } catch (e) {
      setUploadError(e instanceof Error ? e.message : 'Error desconocido');
    } finally {
      setIsLoading(false);
    }
  };

  const handleScan = async () => {
    if (scanType === 'sast' && !targetPath) { setScanError('Sube un archivo antes de iniciar SAST'); return; }
    if (scanType === 'dast' && !targetUrl)  { setScanError('Ingresa una URL válida para DAST'); return; }
    if (scanType === 'hybrid' && (!selectedSastId || !selectedDastId)) { setScanError('Selecciona un escaneo SAST y uno DAST'); return; }

    setIsLoading(true);
    setScanError('');
    setScanResult(null);
    setShowRaw(false);

    const fd = new FormData();
    let endpoint = '';
    if (scanType === 'sast') {
      fd.append('target_path', targetPath);
      fd.append('tool', tool);
      endpoint = '/scan/sast';
    } else if (scanType === 'dast') {
      fd.append('target_url', targetUrl);
      endpoint = '/scan/dast';
    } else {
      fd.append('sast_scan_id', selectedSastId);
      fd.append('dast_scan_id', selectedDastId);
      endpoint = '/scan/hybrid';
    }

    try {
      const res = await fetch(`${API}${endpoint}`, { method: 'POST', body: fd });
      if (!res.ok) throw new Error((await res.json()).detail || 'Error en análisis');
      const data = await res.json();
      setScanResult(data);
      fetchResults();
    } catch (e) {
      setScanError(e instanceof Error ? e.message : 'Error desconocido');
    } finally {
      setIsLoading(false);
    }
  };

  const downloadFile = async (url: string, filename: string) => {
    setDownloadError('');
    setDownloadMessage('');
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
      const blob = await res.blob();
      const a = Object.assign(document.createElement('a'), {
        href: URL.createObjectURL(blob),
        download: filename,
      });
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(a.href);
      setDownloadMessage(`${filename} descargado`);
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : String(e));
    }
  };

  const fetchResults = async () => {
    try {
      const res = await fetch(`${API}/scan-results`);
      if (res.ok) setResults(await res.json());
    } catch {}
  };

  const findings = scanResult ? parseFindings(scanResult) : [];
  const canScan  = !isLoading &&
    !(scanType === 'sast' && !targetPath) &&
    !(scanType === 'hybrid' && (!selectedSastId || !selectedDastId));

  // DataTable computations
  const dtFiltered = useMemo(() => {
    const term = dtSearch.toLowerCase();
    let rows = term
      ? results.filter(r =>
          r.scan_type.toLowerCase().includes(term) ||
          r.tool.toLowerCase().includes(term) ||
          r.status.toLowerCase().includes(term) ||
          (r.target || r.result_path || '').toLowerCase().includes(term))
      : results;

    if (dtSort) {
      rows = [...rows].sort((a, b) => {
        const va = String((a as Record<string, unknown>)[dtSort] ?? '');
        const vb = String((b as Record<string, unknown>)[dtSort] ?? '');
        return dtDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
      });
    }
    return rows;
  }, [results, dtSearch, dtSort, dtDir]);

  const dtTotalPages = Math.max(1, Math.ceil(dtFiltered.length / DT_PAGE_SIZE));
  const dtRows = dtFiltered.slice((dtPage - 1) * DT_PAGE_SIZE, dtPage * DT_PAGE_SIZE);

  function dtToggleSort(field: SortField) {
    if (dtSort === field) setDtDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setDtSort(field); setDtDir('desc'); }
    setDtPage(1);
  }

  function dtSortIcon(field: SortField) {
    if (dtSort !== field) return <span className="sort-icon inactive">↕</span>;
    return <span className="sort-icon active">{dtDir === 'asc' ? '↑' : '↓'}</span>;
  }

  const totalScans = results.length;
  const sastCount  = results.filter(r => r.scan_type === 'SAST').length;
  const dastCount  = results.filter(r => r.scan_type === 'DAST').length;

  return (
    <div className="app-shell">

      {/* ── TOP NAV ── */}
      <nav className="top-nav">
        <div className="nav-brand">
          <div className="nav-logo"><Icons.Shield size={20} /></div>
          <span className="nav-title">HybridSecScan</span>
          <span className="nav-subtitle">OWASP API Security · UNMSM</span>
        </div>

        <div className="nav-tabs">
          <button
            className={`nav-tab ${activePage === 'scanner' ? 'active' : ''}`}
            onClick={() => setActivePage('scanner')}
          >
            <Icons.Shield size={15} /> Scanner
          </button>
          <button
            className={`nav-tab ${activePage === 'research' ? 'active' : ''}`}
            onClick={() => setActivePage('research')}
          >
            <Icons.Chart /> Investigación
          </button>
        </div>

        <div className="nav-status">
          <span className="pulse-dot" />
          <span>Sistema Activo</span>
        </div>
      </nav>

      {activePage === 'research' ? (
        <ResearchDashboard />
      ) : (
        <div className="app-container">

          {/* ── STATS ROW ── */}
          <div className="stats-row">
            <div className="stat-card">
              <span className="stat-value">{totalScans}</span>
              <span className="stat-label">Auditorías</span>
            </div>
            <div className="stat-card">
              <span className="stat-value sast-color">{sastCount}</span>
              <span className="stat-label">Escaneos SAST</span>
            </div>
            <div className="stat-card">
              <span className="stat-value dast-color">{dastCount}</span>
              <span className="stat-label">Escaneos DAST</span>
            </div>
            <div className="stat-card">
              <span className="stat-value hybrid-color">{results.filter(r => r.scan_type === 'HYBRID').length}</span>
              <span className="stat-label">Correlaciones</span>
            </div>
          </div>

          <div className="main-grid">

            {/* ── LEFT: CONFIG ── */}
            <div className="config-column">
              <div className="card">
                <div className="card-header">
                  <h2>Configuración de Análisis</h2>
                </div>

                <div className="scan-mode-tabs">
                  {(['sast', 'dast', 'hybrid'] as const).map(mode => (
                    <button
                      key={mode}
                      className={`tab-btn ${mode} ${scanType === mode ? 'active' : ''}`}
                      onClick={() => setScanType(mode)}
                    >
                      {mode === 'sast' && <><Icons.Code /> SAST</>}
                      {mode === 'dast' && <><Icons.Globe /> DAST</>}
                      {mode === 'hybrid' && <><Icons.Merge /> HYBRID</>}
                    </button>
                  ))}
                </div>

                {scanType === 'sast' && (
                  <div className="form-group">
                    <label>Código fuente objetivo</label>
                    <label className="upload-box">
                      <input
                        type="file"
                        onChange={handleFileChange}
                        accept=".py,.js,.ts,.tsx,.java,.cpp,.c,.go,.php,.rb,.cs"
                        disabled={isLoading}
                      />
                      <span className="upload-icon">
                        {selectedFile ? <Icons.Check /> : <Icons.Upload />}
                      </span>
                      <span className="upload-label">
                        {selectedFile ? selectedFile.name : 'Arrastra archivo o haz clic aquí'}
                      </span>
                      <span className="upload-hint">.py .js .ts .java .go .php .rb .cs</span>
                    </label>

                    {selectedFile && !targetPath && (
                      <button className="btn-primary" onClick={handleUpload} disabled={isLoading}>
                        <Icons.Upload /> {isLoading ? 'Subiendo...' : 'Subir Archivo'}
                      </button>
                    )}
                    {uploadError && <div className="msg-error"><Icons.Alert /> {uploadError}</div>}
                    {uploadMessage && <div className="msg-success"><Icons.Check /> {uploadMessage}</div>}

                    <label style={{ marginTop: '1rem' }}>Herramienta SAST</label>
                    <select value={tool} onChange={e => setTool(e.target.value as 'bandit' | 'semgrep')} disabled={isLoading}>
                      <option value="bandit">Bandit — Python Security Linter</option>
                      <option value="semgrep">Semgrep — Pattern Matching</option>
                    </select>

                    {targetPath && (
                      <div className="path-chip">
                        <Icons.File /> <code>{targetPath}</code>
                      </div>
                    )}
                  </div>
                )}

                {scanType === 'dast' && (
                  <div className="form-group">
                    <label>URL objetivo (API REST)</label>
                    <input
                      type="url"
                      value={targetUrl}
                      onChange={e => setTargetUrl(e.target.value)}
                      placeholder="https://api.example.com/v1"
                      disabled={isLoading}
                    />
                    <p className="hint-text">
                      Ejecuta pruebas HTTP activas: cabeceras de seguridad, CORS, rutas sensibles,
                      divulgación de errores, rate limiting y SSL/TLS.
                    </p>
                  </div>
                )}

                {scanType === 'hybrid' && (
                  <div className="form-group">
                    <label>Correlación SAST + DAST</label>
                    <p className="hint-text">
                      El motor Random Forest correlaciona hallazgos estáticos y dinámicos
                      para reducir falsos positivos en hasta un 40%.
                    </p>

                    <label>Escaneo SAST base</label>
                    <select value={selectedSastId} onChange={e => setSelectedSastId(e.target.value)} disabled={isLoading}>
                      <option value="">— Selecciona SAST —</option>
                      {results.filter(r => r.scan_type === 'SAST').map(r => (
                        <option key={r.id} value={r.id}>
                          #{r.id} · {r.tool} · {new Date(r.created_at).toLocaleString()}
                        </option>
                      ))}
                    </select>

                    <label style={{ marginTop: '1rem' }}>Escaneo DAST base</label>
                    <select value={selectedDastId} onChange={e => setSelectedDastId(e.target.value)} disabled={isLoading}>
                      <option value="">— Selecciona DAST —</option>
                      {results.filter(r => r.scan_type === 'DAST').map(r => (
                        <option key={r.id} value={r.id}>
                          #{r.id} · {r.tool} · {new Date(r.created_at).toLocaleString()}
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                <button className="btn-scan" onClick={handleScan} disabled={!canScan}>
                  {isLoading
                    ? <><span className="spin-ring" /> Analizando...</>
                    : <><Icons.Play /> Ejecutar Auditoría</>}
                </button>

                {scanError && <div className="msg-error"><Icons.Alert /> {scanError}</div>}
              </div>
            </div>

            {/* ── RIGHT: RESULTS ── */}
            <div className="results-column">
              <div className="card" style={{ flex: 1 }}>
                <div className="card-header results-header">
                  <h2>Consola de Resultados</h2>
                  {scanResult && (
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      <button
                        className={`toggle-raw ${showRaw ? 'active' : ''}`}
                        onClick={() => setShowRaw(v => !v)}
                      >
                        {showRaw ? 'Ver Hallazgos' : 'Ver JSON'}
                      </button>
                      <button className="btn-sm" onClick={() => downloadFile(`${API}/download/pdf/${(scanResult as any).id}`, `scan_${(scanResult as any).id}.pdf`)}>
                        <Icons.Download /> PDF
                      </button>
                      <button className="btn-sm" onClick={() => downloadFile(`${API}/download/json/${(scanResult as any).id}`, `scan_${(scanResult as any).id}.json`)}>
                        <Icons.Download /> JSON
                      </button>
                    </div>
                  )}
                </div>

                {downloadMessage && <div className="msg-success"><Icons.Check /> {downloadMessage}</div>}
                {downloadError   && <div className="msg-error"><Icons.Alert /> {downloadError}</div>}

                {scanResult ? (
                  <>
                    <ScanSummaryBar result={scanResult} />
                    {showRaw ? (
                      <div className="result-display">
                        <pre>{JSON.stringify(scanResult, null, 2)}</pre>
                      </div>
                    ) : findings.length > 0 ? (
                      <div className="findings-list">
                        {findings.map((f, i) => <FindingCard key={i} f={f} index={i} />)}
                      </div>
                    ) : (
                      <div className="no-findings">
                        <Icons.Check />
                        <p>Sin vulnerabilidades detectadas</p>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="empty-state">
                    {isLoading
                      ? <>
                          <div className="scan-animation">
                            <div className="scan-ring" /><div className="scan-ring delay1" /><div className="scan-ring delay2" />
                            <div className="scan-icon"><Icons.Shield size={32} /></div>
                          </div>
                          <p>Ejecutando análisis de seguridad...</p>
                        </>
                      : <>
                          <Icons.Shield size={40} />
                          <p>Esperando ejecución de análisis</p>
                          <span>Configura un objetivo y presiona Ejecutar Auditoría</span>
                        </>}
                  </div>
                )}
              </div>
            </div>

            {/* ── FULL WIDTH: DATATABLE HISTORY ── */}
            <div className="card history-section">
              <div className="card-header dt-header">
                <h2>Historial de Auditorías</h2>
                <div className="dt-controls">
                  <div className="dt-search-wrap">
                    <span className="dt-search-icon">
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    </span>
                    <input
                      className="dt-search"
                      type="text"
                      placeholder="Buscar por tipo, herramienta, objetivo…"
                      value={dtSearch}
                      onChange={e => { setDtSearch(e.target.value); setDtPage(1); }}
                    />
                    {dtSearch && (
                      <button className="dt-clear" onClick={() => { setDtSearch(''); setDtPage(1); }}>×</button>
                    )}
                  </div>
                  <span className="dt-count">{dtFiltered.length} registro{dtFiltered.length !== 1 ? 's' : ''}</span>
                  <button className="icon-btn" onClick={fetchResults} title="Actualizar">
                    <Icons.Refresh />
                  </button>
                </div>
              </div>

              <div className="table-container">
                {results.length === 0 ? (
                  <div className="dt-empty">
                    <Icons.Shield size={32} />
                    <p>No hay registros de auditoría.</p>
                    <span>Ejecuta tu primer análisis para ver el historial aquí.</span>
                  </div>
                ) : dtRows.length === 0 ? (
                  <div className="dt-empty">
                    <p>Sin resultados para "<b>{dtSearch}</b>"</p>
                  </div>
                ) : (
                  <table className="dt-table">
                    <thead>
                      <tr>
                        <th className="sortable" onClick={() => dtToggleSort('id')}>
                          # {dtSortIcon('id')}
                        </th>
                        <th className="sortable" onClick={() => dtToggleSort('scan_type')}>
                          Tipo {dtSortIcon('scan_type')}
                        </th>
                        <th className="sortable" onClick={() => dtToggleSort('tool')}>
                          Herramienta {dtSortIcon('tool')}
                        </th>
                        <th>Objetivo</th>
                        <th className="sortable" onClick={() => dtToggleSort('status')}>
                          Estado {dtSortIcon('status')}
                        </th>
                        <th className="sortable" onClick={() => dtToggleSort('created_at')}>
                          Fecha {dtSortIcon('created_at')}
                        </th>
                        <th>Acciones</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dtRows.map(r => (
                        <tr key={r.id}>
                          <td className="col-id">#{r.id}</td>
                          <td>
                            <span className={`type-badge ${r.scan_type.toLowerCase()}`}>
                              {r.scan_type}
                            </span>
                          </td>
                          <td className="col-tool">{r.tool}</td>
                          <td>
                            <code className="code-path dt-path" title={r.target || r.result_path}>
                              {(r.target || r.result_path || 'N/A').split(/[/\\]/).pop()}
                            </code>
                          </td>
                          <td>
                            <span className={`status-dot ${r.status === 'failed' ? 'failed' : 'ok'}`}>
                              {r.status}
                            </span>
                          </td>
                          <td className="col-date">
                            {new Date(r.created_at).toLocaleString('es-PE', {
                              day: '2-digit', month: '2-digit', year: 'numeric',
                              hour: '2-digit', minute: '2-digit',
                            })}
                          </td>
                          <td>
                            <div className="dt-actions">
                              <button className="btn-sm" onClick={() => downloadFile(`${API}/download/pdf/${r.id}`, `HybridSecScan_${r.scan_type}_${r.id}.pdf`)}>
                                <Icons.Download /> PDF
                              </button>
                              <button className="btn-sm" onClick={() => downloadFile(`${API}/download/json/${r.id}`, `HybridSecScan_${r.scan_type}_${r.id}.json`)}>
                                <Icons.Download /> JSON
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Paginación */}
              {dtTotalPages > 1 && (
                <div className="dt-pagination">
                  <span className="dt-page-info">
                    Página {dtPage} de {dtTotalPages}
                    &nbsp;·&nbsp;
                    {(dtPage - 1) * DT_PAGE_SIZE + 1}–{Math.min(dtPage * DT_PAGE_SIZE, dtFiltered.length)} de {dtFiltered.length}
                  </span>
                  <div className="dt-page-btns">
                    <button
                      className="dt-page-btn"
                      onClick={() => setDtPage(1)}
                      disabled={dtPage === 1}
                      title="Primera página"
                    >«</button>
                    <button
                      className="dt-page-btn"
                      onClick={() => setDtPage(p => Math.max(1, p - 1))}
                      disabled={dtPage === 1}
                    >‹</button>
                    {Array.from({ length: dtTotalPages }, (_, i) => i + 1)
                      .filter(p => Math.abs(p - dtPage) <= 2)
                      .map(p => (
                        <button
                          key={p}
                          className={`dt-page-btn ${p === dtPage ? 'active' : ''}`}
                          onClick={() => setDtPage(p)}
                        >{p}</button>
                      ))}
                    <button
                      className="dt-page-btn"
                      onClick={() => setDtPage(p => Math.min(dtTotalPages, p + 1))}
                      disabled={dtPage === dtTotalPages}
                    >›</button>
                    <button
                      className="dt-page-btn"
                      onClick={() => setDtPage(dtTotalPages)}
                      disabled={dtPage === dtTotalPages}
                      title="Última página"
                    >»</button>
                  </div>
                </div>
              )}
            </div>

          </div>
        </div>
      )}
    </div>
  );
}

export default App;

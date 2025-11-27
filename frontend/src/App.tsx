import { useState, useEffect } from 'react';
import './App.css';

// --- Types ---
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

// --- SVG Icons (Icons embebidos para no requerir librerías externas) ---
const Icons = {
  Shield: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  Upload: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>,
  Play: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>,
  Refresh: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>,
  Code: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>,
  Globe: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>,
  Check: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
};

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadMessage, setUploadMessage] = useState('');
  const [uploadError, setUploadError] = useState('');
  const [scanType, setScanType] = useState<'sast' | 'dast'>('sast');
  const [tool, setTool] = useState<'bandit' | 'semgrep'>('bandit');
  const [targetPath, setTargetPath] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [scanResult, setScanResult] = useState<object | null>(null);
  const [scanError, setScanError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);

  const API_BASE_URL = 'http://localhost:8000';

  useEffect(() => {
    fetchResults();
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      if (file.size > 10 * 1024 * 1024) {
        setUploadError('El archivo es muy grande. Máximo 10MB permitido.');
        return;
      }
      setSelectedFile(file);
      setUploadError('');
      // Auto upload logic could be placed here if desired
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    setIsLoading(true);
    setUploadError('');
    setUploadMessage('');

    const formData = new FormData();
    formData.append('file', selectedFile);
    
    try {
      const res = await fetch(`${API_BASE_URL}/upload/`, { method: 'POST', body: formData });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || 'Error subiendo archivo');
      }
      const data = await res.json();
      setUploadMessage('Archivo subido correctamente');
      setTargetPath(data.file_path);
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : 'Error desconocido');
    } finally {
      setIsLoading(false);
    }
  };

  const handleScan = async () => {
    if (scanType === 'sast' && !targetPath) {
      setScanError('⚠️ Sube un archivo antes de iniciar SAST');
      return;
    }
    if (scanType === 'dast' && !targetUrl) {
      setScanError('⚠️ Ingresa una URL válida para DAST');
      return;
    }

    setIsLoading(true);
    setScanError('');
    setScanResult(null);

    try {
      const formData = new FormData();
      let endpoint = '';
      if (scanType === 'sast') {
        formData.append('target_path', targetPath);
        formData.append('tool', tool);
        endpoint = '/scan/sast';
      } else {
        formData.append('target_url', targetUrl);
        endpoint = '/scan/dast';
      }
      
      const res = await fetch(`${API_BASE_URL}${endpoint}`, { method: 'POST', body: formData });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || 'Error ejecutando análisis');
      }
      const data = await res.json();
      setScanResult(data);
      fetchResults(); // Refresh history automatically
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Error desconocido');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchResults = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/scan-results`);
      if (res.ok) {
        const data = await res.json();
        setResults(data);
      }
    } catch (error) {
      console.error('Error:', error);
    }
  };

  return (
    <div className="app-container">
      {/* --- HEADER --- */}
      <header className="header">
        <div className="brand">
          <div style={{ color: 'var(--primary)' }}><Icons.Shield /></div>
          <h1>HybridSecScan</h1>
        </div>
        <div className="status-badge">System Ready</div>
      </header>

      <main className="main-grid">
        
        {/* --- LEFT COLUMN: CONFIGURATION --- */}
        <div className="config-column" style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          
          {/* Card: Scan Configuration */}
          <div className="card">
            <div className="card-header">
              <h2>Configuración de Análisis</h2>
            </div>
            
            <div className="scan-mode-tabs">
              <button 
                className={`tab-btn sast ${scanType === 'sast' ? 'active' : ''}`}
                onClick={() => setScanType('sast')}
              >
                <div style={{display:'flex', alignItems:'center', justifyContent:'center', gap:8}}>
                  <Icons.Code /> SAST
                </div>
              </button>
              <button 
                className={`tab-btn dast ${scanType === 'dast' ? 'active' : ''}`}
                onClick={() => setScanType('dast')}
              >
                 <div style={{display:'flex', alignItems:'center', justifyContent:'center', gap:8}}>
                  <Icons.Globe /> DAST
                </div>
              </button>
            </div>

            {scanType === 'sast' ? (
              <div className="form-group fade-in">
                <label>Código Fuente Target</label>
                <div className="upload-box">
                  <input 
                    type="file" 
                    onChange={handleFileChange}
                    accept=".py,.js,.ts,.tsx,.java,.cpp,.c,.go,.php,.rb,.cs"
                    disabled={isLoading}
                  />
                  <span className="upload-icon">📂</span>
                  <p>{selectedFile ? selectedFile.name : "Arrastra archivo o Clic aquí"}</p>
                </div>
                
                {selectedFile && !targetPath && (
                   <button className="btn-primary" onClick={handleUpload} disabled={isLoading} style={{marginTop: '1rem'}}>
                     {isLoading ? 'Subiendo...' : <><Icons.Upload /> Subir Archivo</>}
                   </button>
                )}
                
                {uploadError && <div className="error-msg">{uploadError}</div>}
                {uploadMessage && <div className="success-msg"><Icons.Check /> {uploadMessage}</div>}

                <label style={{marginTop: '1rem'}}>Herramienta de Escaneo</label>
                <select value={tool} onChange={e => setTool(e.target.value as any)} disabled={isLoading}>
                  <option value="bandit">Bandit (Python Security)</option>
                  <option value="semgrep">Semgrep (Static Analysis)</option>
                </select>

                {targetPath && <p style={{fontSize: '0.8rem', color: 'var(--text-muted)'}}>Target: <span className="code-path">{targetPath}</span></p>}
              </div>
            ) : (
              <div className="form-group fade-in">
                <label>URL Objetivo (API Endpoint)</label>
                <input
                  type="url"
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  placeholder="https://api.ejemplo.com/v1"
                  disabled={isLoading}
                />
                <p style={{fontSize: '0.8rem', color: 'var(--text-muted)'}}>El análisis dinámico ejecutará pruebas contra esta URL activa.</p>
              </div>
            )}

            <button className="btn-primary" onClick={handleScan} disabled={isLoading || (scanType === 'sast' && !targetPath)}>
              {isLoading ? 'Auditando...' : <><Icons.Play /> Ejecutar Auditoría</>}
            </button>
            
            {scanError && <div className="error-msg">{scanError}</div>}
          </div>
        </div>

        {/* --- RIGHT COLUMN: RESULTS --- */}
        <div className="results-column" style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
          <div className="card" style={{ flex: 1 }}>
            <div className="card-header">
              <h2>Consola de Resultados</h2>
            </div>
            
            {scanResult ? (
              <div className="result-display">
                 {/* Si quieres formatear JSON más bonito, podrías usar una librería como react-syntax-highlighter, pero esto es nativo */}
                <pre>{JSON.stringify(scanResult, null, 2)}</pre>
              </div>
            ) : (
              <div style={{ 
                height: '100%', display: 'flex', flexDirection: 'column', 
                alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)',
                minHeight: '300px', border: '2px dashed var(--border)', borderRadius: '8px'
              }}>
                <Icons.Shield />
                <p style={{ marginTop: '1rem' }}>Esperando ejecución de análisis...</p>
              </div>
            )}
          </div>
        </div>

        {/* --- BOTTOM ROW: HISTORY --- */}
        <div className="card history-section">
          <div className="card-header" style={{ justifyContent: 'space-between', display: 'flex' }}>
            <h2>Historial de Auditorías</h2>
            <button onClick={fetchResults} title="Actualizar" style={{background:'transparent', color: 'var(--primary)'}}>
              <Icons.Refresh />
            </button>
          </div>
          
          <div className="table-container">
            {results.length === 0 ? (
              <p style={{ padding: '1rem', color: 'var(--text-muted)' }}>No hay registros de auditoría.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Tipo</th>
                    <th>Herramienta</th>
                    <th>Objetivo</th>
                    <th>Estado</th>
                    <th>Fecha</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map(r => (
                    <tr key={r.id}>
                      <td><span className={`badge ${r.scan_type}`}>{r.scan_type}</span></td>
                      <td style={{textTransform: 'capitalize'}}>{r.tool}</td>
                      <td>
                        <span className="code-path">
                          {r.target || (r.result_path ? r.result_path.split('/').pop() : 'N/A')}
                        </span>
                      </td>
                      <td>
                        <span className={`status ${r.status === 'failed' ? 'failed' : 'finished'}`}>
                          {r.status}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                        {new Date(r.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

      </main>
    </div>
  );
}

export default App;
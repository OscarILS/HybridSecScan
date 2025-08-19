import { useState } from 'react';
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

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      // Validate file size (10MB)
      if (file.size > 10 * 1024 * 1024) {
        setUploadError('El archivo es muy grande. Máximo 10MB permitido.');
        return;
      }
      setSelectedFile(file);
      setUploadError('');
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
      const res = await fetch(`${API_BASE_URL}/upload/`, {
        method: 'POST',
        body: formData,
      });
      
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || 'Error subiendo archivo');
      }
      
      const data = await res.json();
      setUploadMessage(data.message);
      setTargetPath(data.file_path);
    } catch (error) {
      setUploadError(error instanceof Error ? error.message : 'Error desconocido');
    } finally {
      setIsLoading(false);
    }
  };

  const handleScan = async () => {
    if (scanType === 'sast' && !targetPath) {
      setScanError('Debe subir un archivo primero para análisis SAST');
      return;
    }
    
    if (scanType === 'dast' && !targetUrl) {
      setScanError('Debe ingresar una URL para análisis DAST');
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
      
      const res = await fetch(`${API_BASE_URL}${endpoint}`, {
        method: 'POST',
        body: formData,
      });
      
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.detail || 'Error ejecutando análisis');
      }
      
      const data = await res.json();
      setScanResult(data);
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Error desconocido');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchResults = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/scan-results`);
      if (!res.ok) {
        throw new Error('Error obteniendo resultados');
      }
      const data = await res.json();
      setResults(data);
    } catch (error) {
      console.error('Error fetching results:', error);
    }
  };

  return (
    <div className="container">
      <h1>HybridSecScan - Auditoría OWASP API Top 10</h1>
      
      <div className="upload-section">
        <h2>Subir código fuente</h2>
        <input 
          type="file" 
          onChange={handleFileChange}
          accept=".py,.js,.ts,.tsx,.java,.cpp,.c,.go,.php,.rb,.cs"
          disabled={isLoading}
        />
        <button onClick={handleUpload} disabled={!selectedFile || isLoading}>
          {isLoading ? 'Subiendo...' : 'Subir'}
        </button>
        {uploadMessage && <p className="success">{uploadMessage}</p>}
        {uploadError && <p className="error">{uploadError}</p>}
      </div>
      
      <div className="scan-section">
        <h2>Ejecutar análisis</h2>
        <div className="scan-type-selection">
          <label>
            <input
              type="radio"
              checked={scanType === 'sast'}
              onChange={() => setScanType('sast')}
              disabled={isLoading}
            />
            SAST (Análisis estático)
          </label>
          <label>
            <input
              type="radio"
              checked={scanType === 'dast'}
              onChange={() => setScanType('dast')}
              disabled={isLoading}
            />
            DAST (Análisis dinámico)
          </label>
        </div>
        
        {scanType === 'sast' ? (
          <div>
            <label>
              Herramienta:
              <select 
                value={tool} 
                onChange={e => setTool(e.target.value as 'bandit' | 'semgrep')}
                disabled={isLoading}
              >
                <option value="bandit">Bandit (Python)</option>
                <option value="semgrep">Semgrep (Multi-lenguaje)</option>
              </select>
            </label>
            {targetPath && <p>Ruta del código: <code>{targetPath}</code></p>}
          </div>
        ) : (
          <div>
            <label>
              URL de la API:
              <input
                type="url"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="https://api.ejemplo.com"
                disabled={isLoading}
              />
            </label>
          </div>
        )}
        
        <button onClick={handleScan} disabled={isLoading}>
          {isLoading ? 'Ejecutando análisis...' : 'Ejecutar análisis'}
        </button>
        
        {scanError && <p className="error">{scanError}</p>}
        
        {scanResult && (
          <div className="result">
            <h3>Resultado del análisis</h3>
            <pre>{typeof scanResult === 'object' ? JSON.stringify(scanResult, null, 2) : String(scanResult)}</pre>
          </div>
        )}
      </div>
      
      <div className="results-section">
        <h2>Historial de análisis</h2>
        <button onClick={fetchResults}>Actualizar historial</button>
        {results.length === 0 ? (
          <p>No hay análisis previos</p>
        ) : (
          <ul>
            {results.map(r => (
              <li key={r.id} className={r.status === 'failed' ? 'failed' : ''}>
                <strong>[{r.scan_type}]</strong> {r.tool}
                <br />
                <small>
                  {r.target && `Target: ${r.target} | `}
                  Estado: {r.status} | {new Date(r.created_at).toLocaleString()}
                </small>
                {r.error_message && (
                  <div className="error-message">Error: {r.error_message}</div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default App;

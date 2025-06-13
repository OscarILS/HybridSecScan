import { useState } from 'react';
import './App.css';

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadMessage, setUploadMessage] = useState('');
  const [scanType, setScanType] = useState<'sast' | 'dast'>('sast');
  const [tool, setTool] = useState<'bandit' | 'semgrep'>('bandit');
  const [targetPath, setTargetPath] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [scanResult, setScanResult] = useState<object | null>(null);
  type ScanResult = {
    id: string | number;
    scan_type: string;
    tool: string;
    result_path: string;
    created_at: string;
  };
  const [results, setResults] = useState<ScanResult[]>([]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) return;
    const formData = new FormData();
    formData.append('file', selectedFile);
    const res = await fetch('http://localhost:8000/upload/', {
      method: 'POST',
      body: formData,
    });
    const data = await res.json();
    setUploadMessage(data.message);
    setTargetPath(data.file_path);
  };

  const handleScan = async () => {
    if (scanType === 'sast') {
      const formData = new FormData();
      formData.append('target_path', targetPath);
      formData.append('tool', tool);
      const res = await fetch('http://localhost:8000/scan/sast', {
        method: 'POST',
        body: formData,
      });
      setScanResult(await res.json());
    } else {
      const formData = new FormData();
      formData.append('target_url', targetUrl);
      const res = await fetch('http://localhost:8000/scan/dast', {
        method: 'POST',
        body: formData,
      });
      setScanResult(await res.json());
    }
  };

  const fetchResults = async () => {
    const res = await fetch('http://localhost:8000/scan-results');
    setResults(await res.json());
  };

  return (
    <div className="container">
      <h1>HybridSecScan - Auditoría OWASP API Top 10</h1>
      <div className="upload-section">
        <h2>Subir código fuente</h2>
        <input type="file" onChange={handleFileChange} />
        <button onClick={handleUpload}>Subir</button>
        <p>{uploadMessage}</p>
      </div>
      <div className="scan-section">
        <h2>Ejecutar análisis</h2>
        <label>
          <input
            type="radio"
            checked={scanType === 'sast'}
            onChange={() => setScanType('sast')}
          />
          SAST
        </label>
        <label>
          <input
            type="radio"
            checked={scanType === 'dast'}
            onChange={() => setScanType('dast')}
          />
          DAST
        </label>
        {scanType === 'sast' ? (
          <div>
            <label>
              Herramienta:
              <select value={tool} onChange={e => setTool(e.target.value as 'bandit' | 'semgrep')}>
                <option value="bandit">Bandit</option>
                <option value="semgrep">Semgrep</option>
              </select>
            </label>
            <p>Ruta del código: <code>{targetPath}</code></p>
          </div>
        ) : (
          <div>
            <label>
              URL de la API:
              <input
                type="text"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="http://localhost:8000/api"
              />
            </label>
          </div>
        )}
        <button onClick={handleScan}>Ejecutar análisis</button>
        {scanResult && (
          <div className="result">
            <h3>Resultado</h3>
            <pre>{typeof scanResult === 'object' ? JSON.stringify(scanResult, null, 2) : String(scanResult)}</pre>
          </div>
        )}
      </div>
      <div className="results-section">
        <h2>Historial de análisis</h2>
        <button onClick={fetchResults}>Actualizar</button>
        <ul>
          {results.map(r => (
            <li key={r.id}>
              [{r.scan_type}] {r.tool} - {r.result_path} ({r.created_at})
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default App;

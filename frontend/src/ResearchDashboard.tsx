import React, { useEffect, useState } from 'react';
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import './ResearchDashboard.css';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Todo lo que muestra este panel sale de archivos de resultados generados por el
// código del proyecto; no hay métricas escritas a mano:
//   /api/model-metrics     → data/models/metadata.json          (backend/train_ml_model.py)
//   /api/scale-evaluation  → data/experiments/scale_evaluation_* (scripts/run_scale_evaluation.py --save)

interface SplitMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc: number;
}

interface TrainingInfo {
  n_train_samples: number;
  n_val_samples: number;
  n_test_samples: number;
  n_features: number;
  trained_at: string;
}

interface ModelInfo {
  model_available: boolean;
  metrics?: SplitMetrics;
  validation?: SplitMetrics;
  training_info?: TrainingInfo;
  confusion_matrix?: { TN: number; FP: number; FN: number; TP: number };
}

interface MethodStats {
  mean_f1: number;
  mean_precision: number;
  mean_recall: number;
}

interface AppMethod {
  findings: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
}

interface PairedTest {
  t: number;
  p_one_tailed: number;
  p_two_tailed: number;
  cohens_d?: number;
  significant: boolean;
}

interface ScaleEvaluation {
  available: boolean;
  source?: string;
  n_apps?: number;
  sast?: MethodStats;
  dast?: MethodStats;
  hybrid?: MethodStats;
  statistical_tests?: {
    df?: number;
    hybrid_vs_sast?: PairedTest;
    hybrid_vs_dast?: PairedTest;
    recall_hybrid_vs_sast?: PairedTest;
  };
  per_app?: Record<string, { ground_truth_n: number; sast: AppMethod; dast: AppMethod; hybrid: AppMethod }>;
}

const TOOLTIP_STYLE = { background: '#1e293b', border: '1px solid #334155', borderRadius: 8 };
const AXIS_TICK = { fill: '#64748b', fontSize: 11 };
const AXIS_LINE = { stroke: '#334155' };

const pct = (v?: number) => (v === undefined ? '—' : `${(v * 100).toFixed(1)}%`);
const dec = (v?: number, digits = 3) => (v === undefined ? '—' : v.toFixed(digits));

const ResearchDashboard: React.FC = () => {
  const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);
  const [scaleEval, setScaleEval] = useState<ScaleEvaluation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const [modelResp, scaleResp] = await Promise.all([
          fetch(`${API_BASE}/api/model-metrics`),
          fetch(`${API_BASE}/api/scale-evaluation`),
        ]);
        setModelInfo(await modelResp.json());
        setScaleEval(await scaleResp.json());
      } catch (err) {
        console.error('Error cargando métricas de investigación:', err);
        setError('No se pudo conectar con el backend. Inícialo y recarga la página.');
      } finally {
        setIsLoading(false);
      }
    };
    load();
  }, []);

  if (isLoading) {
    return (
      <div className="research-dashboard loading">
        <div className="loading-spinner">Cargando métricas de investigación...</div>
      </div>
    );
  }

  const m = modelInfo?.metrics;
  const v = modelInfo?.validation;
  const ti = modelInfo?.training_info;
  const cm = modelInfo?.confusion_matrix;

  const modelChart =
    m && v
      ? [
          { metric: 'Accuracy', validacion: v.accuracy, test: m.accuracy },
          { metric: 'Precision', validacion: v.precision, test: m.precision },
          { metric: 'Recall', validacion: v.recall, test: m.recall },
          { metric: 'F1', validacion: v.f1_score, test: m.f1_score },
          { metric: 'ROC-AUC', validacion: v.roc_auc, test: m.roc_auc },
        ]
      : [];

  const scaleOk = scaleEval?.available && scaleEval.sast && scaleEval.dast && scaleEval.hybrid;
  const methodChart = scaleOk
    ? (['sast', 'dast', 'hybrid'] as const).map((k) => ({
        method: k === 'hybrid' ? 'Híbrido' : k.toUpperCase(),
        precision: scaleEval![k]!.mean_precision,
        recall: scaleEval![k]!.mean_recall,
        f1: scaleEval![k]!.mean_f1,
      }))
    : [];
  const perAppChart = scaleOk
    ? Object.entries(scaleEval!.per_app ?? {}).map(([app, r]) => ({
        app,
        SAST: r.sast.f1,
        DAST: r.dast.f1,
        Híbrido: r.hybrid.f1,
      }))
    : [];
  const tests = scaleEval?.statistical_tests;

  return (
    <div className="research-dashboard">
      <h1>🔬 Dashboard de Investigación - HybridSecScan</h1>

      {error && <div className="model-warning">⚠️ {error}</div>}
      {modelInfo && !modelInfo.model_available && (
        <div className="model-warning">
          ⚠️ Modelo ML no entrenado. Ejecuta:
          <code> python scripts/generate_training_dataset.py &amp;&amp; python backend/train_ml_model.py</code>
        </div>
      )}
      {ti && (
        <div className="model-badge">
          ✅ Modelo entrenado — {(ti.n_train_samples + ti.n_val_samples + ti.n_test_samples).toLocaleString()} pares
          sintéticos · {ti.n_features} features · Entrenado el {new Date(ti.trained_at).toLocaleDateString('es-PE')}
        </div>
      )}

      {/* ── Modelo ML: métricas en el conjunto de test ─────────────────────── */}
      <div className="metrics-overview">
        <div className="metric-card">
          <h3>Recall (test)</h3>
          <div className="metric-value">{pct(m?.recall)}</div>
          <div className="metric-improvement">Prioridad: no omitir vulnerabilidades reales</div>
        </div>
        <div className="metric-card">
          <h3>Precision (test)</h3>
          <div className="metric-value">{pct(m?.precision)}</div>
          <div className="metric-improvement">Costo del recall alto: más falsas alarmas</div>
        </div>
        <div className="metric-card">
          <h3>F1-Score (test)</h3>
          <div className="metric-value">{dec(m?.f1_score)}</div>
          <div className="metric-improvement">Accuracy: {pct(m?.accuracy)}</div>
        </div>
        <div className="metric-card">
          <h3>ROC-AUC (test)</h3>
          <div className="metric-value">{dec(m?.roc_auc)}</div>
          <div className="metric-improvement">Capacidad discriminativa del modelo</div>
        </div>
      </div>

      {modelChart.length > 0 && (
        <div className="chart-section">
          <h2>🤖 Random Forest — Validación vs Test</h2>
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={modelChart} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="metric" tick={AXIS_TICK} axisLine={AXIS_LINE} />
              <YAxis domain={[0, 1]} tick={AXIS_TICK} axisLine={AXIS_LINE} />
              <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#f8fafc' }} />
              <Legend wrapperStyle={{ color: '#94a3b8', fontSize: 12 }} />
              <Bar dataKey="validacion" fill="#a78bfa" name="Validación" radius={[3, 3, 0, 0]} />
              <Bar dataKey="test" fill="#fbbf24" name="Test" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {cm && ti && (
        <div className="results-table-section">
          <h2>🧮 Matriz de Confusión (test, n = {ti.n_test_samples})</h2>
          <div className="table-container">
            <table className="results-table">
              <thead>
                <tr>
                  <th></th>
                  <th>Predicho: no correlacionado</th>
                  <th>Predicho: correlacionado</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Real: no correlacionado</td>
                  <td>TN = {cm.TN}</td>
                  <td>FP = {cm.FP}</td>
                </tr>
                <tr>
                  <td>Real: correlacionado</td>
                  <td>FN = {cm.FN}</td>
                  <td>TP = {cm.TP}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Evaluación a escala: 4 apps vulnerables vs ground truth ───────── */}
      {scaleOk ? (
        <>
          <div className="chart-section">
            <h2>🧪 Evaluación en {scaleEval!.n_apps} aplicaciones vulnerables (media por método)</h2>
            <p className="metric-improvement">
              “Híbrido” = unión de los hallazgos SAST y DAST contra el ground truth. Mide la cobertura combinada; no
              aplica el motor de correlación.
            </p>
            <ResponsiveContainer width="100%" height={320}>
              <BarChart data={methodChart} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="method" tick={AXIS_TICK} axisLine={AXIS_LINE} />
                <YAxis domain={[0, 1]} tick={AXIS_TICK} axisLine={AXIS_LINE} />
                <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#f8fafc' }} />
                <Legend wrapperStyle={{ color: '#94a3b8', fontSize: 12 }} />
                <Bar dataKey="precision" fill="#a78bfa" name="Precision" radius={[3, 3, 0, 0]} />
                <Bar dataKey="recall" fill="#34d399" name="Recall" radius={[3, 3, 0, 0]} />
                <Bar dataKey="f1" fill="#fbbf24" name="F1" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="chart-section">
            <h2>📊 F1 por aplicación</h2>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={perAppChart} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="app" tick={AXIS_TICK} axisLine={AXIS_LINE} />
                <YAxis domain={[0, 1]} tick={AXIS_TICK} axisLine={AXIS_LINE} />
                <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#f8fafc' }} />
                <Legend wrapperStyle={{ color: '#94a3b8', fontSize: 12 }} />
                <Bar dataKey="SAST" fill="#38bdf8" radius={[3, 3, 0, 0]} />
                <Bar dataKey="DAST" fill="#f87171" radius={[3, 3, 0, 0]} />
                <Bar dataKey="Híbrido" fill="#34d399" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {tests && (
            <div className="results-table-section">
              <h2>📐 Prueba t emparejada (gl = {tests.df ?? '—'}; H₁: híbrido &gt; método individual)</h2>
              <div className="table-container">
                <table className="results-table">
                  <thead>
                    <tr>
                      <th>Comparación</th>
                      <th>t</th>
                      <th>p unilateral</th>
                      <th>p bilateral</th>
                      <th>¿Significativa (p &lt; 0.05)?</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(
                      [
                        ['F1: Híbrido vs SAST', tests.hybrid_vs_sast],
                        ['F1: Híbrido vs DAST', tests.hybrid_vs_dast],
                        ['Recall: Híbrido vs SAST', tests.recall_hybrid_vs_sast],
                      ] as [string, PairedTest | undefined][]
                    )
                      .filter(([, r]) => r)
                      .map(([label, r]) => (
                        <tr key={label} className={r!.significant ? 'highlight' : ''}>
                          <td>{label}</td>
                          <td>{dec(r!.t, 2)}</td>
                          <td>{dec(r!.p_one_tailed)}</td>
                          <td>{dec(r!.p_two_tailed)}</td>
                          <td>{r!.significant ? 'Sí (unilateral)' : 'No'}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
              <p className="metric-improvement">
                Fuente: <code>data/experiments/{scaleEval!.source}</code>. Con {scaleEval!.n_apps} aplicaciones la
                potencia estadística es baja.
              </p>
            </div>
          )}
        </>
      ) : (
        <div className="model-warning">
          ⚠️ Sin evaluación a escala. Ejecuta: <code>python scripts/run_scale_evaluation.py --save</code>
        </div>
      )}

      {/* ── Cómo funciona la correlación ──────────────────────────────────── */}
      <div className="theoretical-foundations">
        <h2>🧠 Motor de Correlación</h2>
        <div className="foundation-cards">
          <div className="foundation-card">
            <h3>1. Confianza ponderada</h3>
            <div className="theory-content">
              <p>Endpoint 40% · Tipo 35% · Similitud semántica 10% · Random Forest 10% · Severidad 5%</p>
              <p>Umbral de correlación: 0.70 con modelo ML.</p>
              <p>Los pesos y el umbral son decisiones de diseño, no resultado de una optimización.</p>
            </div>
          </div>

          <div className="foundation-card">
            <h3>2. Random Forest</h3>
            <div className="theory-content">
              <p>200 árboles, profundidad máxima 20, <code>class_weight=balanced</code>.</p>
              <p>517 features: 500 TF-IDF + 8 categóricas + 9 numéricas.</p>
              <p>Dataset sintético de 1,300 pares en 6 categorías (incluye negativos difíciles), split 80/10/10.</p>
            </div>
          </div>

          <div className="foundation-card">
            <h3>3. Resultados de correlación</h3>
            <div className="theory-content">
              <p>
                App vulnerable (Flask): 1 correlación confirmada — SQL injection en <code>/login</code>, detectada por
                Bandit (SAST) y por el escáner activo (DAST).
              </p>
              <p>OWASP Juice Shop: 0 correlaciones sobre el umbral.</p>
            </div>
          </div>

          <div className="foundation-card">
            <h3>4. Limitaciones</h3>
            <div className="theory-content">
              <p>
                <strong>Domain shift:</strong> el TF-IDF aprendió el vocabulario sintético y no reconoce el de Semgrep
                o el escáner HTTP; reentrenar con salidas reales queda como trabajo futuro.
              </p>
              <p>
                <strong>Muestra pequeña:</strong> {scaleEval?.n_apps ?? 4} aplicaciones; las pruebas estadísticas
                tienen poca potencia.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResearchDashboard;

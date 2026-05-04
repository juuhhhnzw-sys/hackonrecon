import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { createScan, getApiBase, getScanResult, getScanStatus } from "./api";

const severityColor = {
  SAFE: "#16a34a",
  LOW: "#65a30d",
  MEDIUM: "#ca8a04",
  HIGH: "#ea580c",
  EXTREME: "#dc2626"
};

const barGradient = ["#7c3aed", "#8b5cf6", "#a78bfa", "#c4b5fd", "#ddd6fe"];

function scoreToSeverity(score) {
  if (score <= 20) return "SAFE";
  if (score <= 40) return "LOW";
  if (score <= 60) return "MEDIUM";
  if (score <= 80) return "HIGH";
  return "EXTREME";
}

function todayLabel() {
  return new Date().toLocaleDateString("pt-BR", {
    weekday: "long",
    day: "numeric",
    month: "long",
    year: "numeric"
  });
}

export default function App() {
  const [form, setForm] = useState({ target: "", max_workers: 6, timeout: 12 });
  const [loading, setLoading] = useState(false);
  const [scan, setScan] = useState(null);
  const [error, setError] = useState("");

  const chartData = useMemo(() => {
    if (!scan) return [];
    return [
      { label: "Ports", value: (scan.ports || []).length },
      { label: "HTTP", value: (scan.http || []).length },
      { label: "Dirs", value: (scan.directories || []).length },
      { label: "Subs", value: (scan.subdomains || []).length },
      { label: "Findings", value: (scan.findings || []).length }
    ];
  }, [scan]);

  const feedFindings = useMemo(() => {
    const list = scan?.findings || [];
    return [...list].slice(-12).reverse();
  }, [scan]);

  const reportHref =
    scan?.id != null ? `${getApiBase()}/api/scans/${encodeURIComponent(scan.id)}/report.md` : null;

  async function handleStartScan(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setScan(null);

    try {
      const created = await createScan(form);
      let status = created.status;
      let lastError = "";

      const maxAttempts = 120;
      const delayMs = 1000;
      for (let i = 0; i < maxAttempts && status !== "done" && status !== "failed"; i += 1) {
        await new Promise((r) => setTimeout(r, delayMs));
        const s = await getScanStatus(created.id);
        status = s.status;
        lastError = s.error || "";
        if (status === "done" || status === "failed") break;
      }

      if (status === "failed") {
        throw new Error(lastError || "Scan failed on backend.");
      }

      const result = await getScanResult(created.id);
      setScan(result);
    } catch (err) {
      setError(err.message || "Unexpected error");
    } finally {
      setLoading(false);
    }
  }

  const risk = scan?.overall_risk ?? 0;
  const riskSeverity = scoreToSeverity(risk);
  const nPorts = scan?.ports?.length ?? 0;
  const nHttp = scan?.http?.length ?? 0;
  const nDirs = scan?.directories?.length ?? 0;
  const nFindings = scan?.findings?.length ?? 0;

  return (
    <div className="app-shell">
      <aside className="sidebar glass-sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden />
          <div>
            <div className="brand-title">HackOn</div>
            <div className="brand-sub">Recon</div>
          </div>
        </div>

        <nav className="nav" aria-label="Principal">
          <button type="button" className="nav-item nav-item-active">
            <span className="nav-icon" aria-hidden>
              ◆
            </span>
            Dashboard
          </button>
          <a className="nav-item nav-item-link" href={getApiBase() + "/docs"} target="_blank" rel="noreferrer">
            <span className="nav-icon" aria-hidden>
              ↗
            </span>
            API docs
          </a>
        </nav>

        <div className="nav-section-label">Status</div>
        <div className="api-pill">
          <span className="dot dot-live" />
          <span className="api-pill-text">{getApiBase().replace(/^https?:\/\//, "")}</span>
        </div>

        {reportHref && (
          <a className="cta-premium" href={reportHref} target="_blank" rel="noreferrer">
            <div className="cta-premium-title">Relatório Markdown</div>
            <div className="cta-premium-desc">Abrir arquivo gerado pelo scan</div>
            <span className="cta-premium-btn">Exportar</span>
          </a>
        )}
      </aside>

      <div className="main-column">
        <header className="topbar glass-top">
          <div>
            <h1 className="page-title">Dashboard</h1>
            <p className="page-sub">Recon autorizado · visão consolidada do alvo</p>
          </div>
          <div className="topbar-meta">
            <span className="date-pill">{todayLabel()}</span>
          </div>
        </header>

        <main className="main-scroll">
          <section className="glass-card scan-card">
            <div className="scan-card-head">
              <h2 className="section-title">Novo scan</h2>
              <p className="section-hint">Alvo, paralelismo e timeout são enviados ao Orchestrator via API.</p>
            </div>
            <form className="scan-form" onSubmit={handleStartScan}>
              <label className="field">
                <span className="field-label">Alvo (domínio ou IP)</span>
                <input
                  required
                  className="field-input"
                  placeholder="exemplo.com"
                  value={form.target}
                  onChange={(e) => setForm((prev) => ({ ...prev, target: e.target.value }))}
                />
              </label>
              <label className="field">
                <span className="field-label">Max workers</span>
                <input
                  type="number"
                  min={1}
                  max={32}
                  className="field-input"
                  value={form.max_workers}
                  onChange={(e) => setForm((prev) => ({ ...prev, max_workers: Number(e.target.value) }))}
                />
              </label>
              <label className="field">
                <span className="field-label">Timeout (s)</span>
                <input
                  type="number"
                  min={1}
                  max={120}
                  className="field-input"
                  value={form.timeout}
                  onChange={(e) => setForm((prev) => ({ ...prev, timeout: Number(e.target.value) }))}
                />
              </label>
              <button disabled={loading} type="submit" className="btn-primary">
                {loading ? (
                  <>
                    <span className="spinner" aria-hidden />
                    Executando…
                  </>
                ) : (
                  "Run recon"
                )}
              </button>
            </form>
            {error && <p className="error-banner">{error}</p>}
          </section>

          {scan && (
            <>
              <div className="metrics-row">
                <div className="metric glass-metric">
                  <span className="metric-label">Portas abertas</span>
                  <span className="metric-value">{nPorts}</span>
                  <span className="metric-foot">TCP connect</span>
                </div>
                <div className="metric glass-metric">
                  <span className="metric-label">Probes HTTP</span>
                  <span className="metric-value">{nHttp}</span>
                  <span className="metric-foot">GET + metadados</span>
                </div>
                <div className="metric glass-metric">
                  <span className="metric-label">Endpoints</span>
                  <span className="metric-value">{nDirs}</span>
                  <span className="metric-foot">Wordlist curta</span>
                </div>
                <div className="metric glass-metric metric-accent">
                  <span className="metric-label">Risk score</span>
                  <span className="metric-value metric-risk">{risk}</span>
                  <span className="metric-foot" style={{ color: severityColor[riskSeverity] }}>
                    {riskSeverity}
                  </span>
                </div>
              </div>

              <div className="modules-row">
                {[
                  { label: "Port scanner", ok: nPorts >= 0 },
                  { label: "HTTP probe", ok: nHttp >= 0 },
                  { label: "Dir fuzzer", ok: nDirs >= 0 },
                  { label: "Subdomain enum", ok: (scan.subdomains || []).length > 0 }
                ].map((m) => (
                  <div key={m.label} className="module-chip glass-metric">
                    <span className="module-dot">{m.ok ? "✓" : "—"}</span>
                    <span className="module-name">{m.label}</span>
                    <span className="module-pct">100%</span>
                  </div>
                ))}
              </div>

              <div className="split-hero">
                <section className="hero-card">
                  <div className="hero-card-inner">
                    <div className="hero-top">
                      <div>
                        <p className="hero-kicker">Alvo</p>
                        <p className="hero-target">{scan.target}</p>
                      </div>
                      <div className="hero-score-wrap">
                        <p className="hero-kicker">Score</p>
                        <p className="hero-score" style={{ color: severityColor[riskSeverity] }}>
                          {risk}
                          <span className="hero-score-max">/100</span>
                        </p>
                      </div>
                    </div>
                    <p className="hero-caption">Distribuição de artefatos coletados</p>
                    <div className="chart-wrap">
                      <ResponsiveContainer width="100%" height={220}>
                        <BarChart data={chartData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                          <XAxis dataKey="label" tick={{ fill: "rgba(255,255,255,0.65)", fontSize: 11 }} axisLine={false} tickLine={false} />
                          <YAxis allowDecimals={false} tick={{ fill: "rgba(255,255,255,0.45)", fontSize: 11 }} axisLine={false} tickLine={false} />
                          <Tooltip
                            cursor={{ fill: "rgba(255,255,255,0.06)" }}
                            contentStyle={{
                              background: "rgba(15,8,35,0.92)",
                              border: "1px solid rgba(255,255,255,0.12)",
                              borderRadius: "12px",
                              color: "#f5f3ff"
                            }}
                          />
                          <Bar dataKey="value" radius={[10, 10, 4, 4]} maxBarSize={48}>
                            {chartData.map((_, i) => (
                              <Cell key={chartData[i].label} fill={barGradient[i % barGradient.length]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </section>

                <aside className="feed-card glass-card">
                  <h3 className="feed-title">Findings recentes</h3>
                  <ul className="feed-list">
                    {feedFindings.length === 0 ? (
                      <li className="feed-empty">Nenhum finding neste scan.</li>
                    ) : (
                      feedFindings.map((f, idx) => (
                        <li key={`feed-${idx}-${f.risk_score}-${f.type}`} className="feed-item">
                          <span className="feed-sev" style={{ background: severityColor[f.severity] || "#94a3b8" }} title={f.severity} />
                          <div className="feed-body">
                            <div className="feed-line1">{f.type}</div>
                            <div className="feed-line2">{String(f.value).slice(0, 80)}</div>
                          </div>
                          <span className="feed-score">{f.risk_score}</span>
                        </li>
                      ))
                    )}
                  </ul>
                </aside>
              </div>

              <div className="grid-2">
                <section className="glass-card panel">
                  <h3 className="panel-title">Portas abertas</h3>
                  <ul className="clean-list">
                    {(scan.ports || []).map((p) => (
                      <li key={`${p.port}-${p.service_guess}`}>
                        <span className="pill-port">{p.port}</span>
                        <span className="pill-svc">{p.service_guess}</span>
                      </li>
                    ))}
                  </ul>
                </section>
                <section className="glass-card panel">
                  <h3 className="panel-title">Subdomínios</h3>
                  <ul className="clean-list">
                    {(scan.subdomains || []).map((s) => (
                      <li key={s.subdomain}>
                        <span className="sub-name">{s.subdomain}</span>
                        <span className={s.resolved ? "sub-ok" : "sub-bad"}>{s.resolved ? s.ip || "OK" : "—"}</span>
                      </li>
                    ))}
                  </ul>
                </section>
              </div>

              <section className="glass-card panel">
                <h3 className="panel-title">Endpoints descobertos</h3>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Path</th>
                        <th>Status</th>
                        <th>URL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(scan.directories || []).length === 0 ? (
                        <tr>
                          <td colSpan={3} className="muted">
                            Nenhum hit em 200 / 301 / 302 / 403 com a wordlist padrão.
                          </td>
                        </tr>
                      ) : (
                        (scan.directories || []).map((d, idx) => (
                          <tr key={`${d.url}-${idx}`}>
                            <td>
                              <code className="code-tag">{d.path}</code>
                            </td>
                            <td>{d.status_code}</td>
                            <td className="td-url">{d.url}</td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="glass-card panel">
                <h3 className="panel-title">HTTP probes</h3>
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Título</th>
                        <th>Server</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(scan.http || []).map((h, idx) => (
                        <tr key={`${h.url}-${idx}`}>
                          <td className="td-url">{h.url}</td>
                          <td>{h.status_code}</td>
                          <td>{h.title || "—"}</td>
                          <td>
                            <span className="server-tag">{h.server || "—"}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="glass-card panel panel-wide">
                <h3 className="panel-title">Risk findings (completo)</h3>
                <div className="table-wrap table-tall">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Score</th>
                        <th>Tipo</th>
                        <th>Valor</th>
                        <th>Motivo</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(scan.findings || []).map((f, idx) => (
                        <tr key={`${f.type}-${f.value}-${idx}`}>
                          <td>
                            <span className="sev-badge" style={{ color: severityColor[f.severity] }}>
                              {f.severity}
                            </span>
                          </td>
                          <td>{f.risk_score}</td>
                          <td>{f.type}</td>
                          <td className="td-mono">{f.value}</td>
                          <td>{f.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {!scan && !loading && (
            <section className="glass-card empty-state">
              <p className="empty-title">Pronto para o primeiro scan</p>
              <p className="empty-text">Preencha o alvo acima e execute o recon. Os gráficos e listas aparecem aqui após a conclusão.</p>
            </section>
          )}
        </main>
      </div>
    </div>
  );
}

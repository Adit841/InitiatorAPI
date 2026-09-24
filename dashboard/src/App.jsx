import { useEffect, useMemo, useState } from 'react'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['all', 'vulnerable', 'secure']

function severityRank(s) {
  return SEVERITIES.indexOf(s)
}

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function EvidenceBlock({ evidence }) {
  if (!evidence || typeof evidence !== 'object') return null
  return (
    <dl className="evidence">
      {Object.entries(evidence).map(([key, value]) => (
        <div key={key} className="evidence-row">
          <dt>{key}</dt>
          <dd>
            {Array.isArray(value) ? (
              <ul className="chip-list">
                {value.map((item) => (
                  <li key={String(item)} className="chip">
                    {String(item)}
                  </li>
                ))}
              </ul>
            ) : typeof value === 'object' && value !== null ? (
              <pre>{JSON.stringify(value, null, 2)}</pre>
            ) : (
              <code>{String(value)}</code>
            )}
          </dd>
        </div>
      ))}
    </dl>
  )
}

function FindingCard({ finding, expanded, onToggle }) {
  return (
    <article
      className={`finding severity-${finding.severity} status-${finding.status} ${expanded ? 'open' : ''}`}
    >
      <button type="button" className="finding-header" onClick={onToggle} aria-expanded={expanded}>
        <div className="finding-meta">
          <span className={`badge severity`}>{finding.severity}</span>
          <span className={`badge status`}>{finding.status}</span>
          <span className="finding-id">{finding.id}</span>
        </div>
        <h2>{finding.title}</h2>
        <p className="endpoint">
          <code>{finding.endpoint}</code>
        </p>
        <span className="chevron" aria-hidden>
          {expanded ? '−' : '+'}
        </span>
      </button>

      {expanded && (
        <div className="finding-body">
          <p className="description">{finding.description}</p>

          <section>
            <h3>Evidence</h3>
            <EvidenceBlock evidence={finding.evidence} />
          </section>

          {finding.reproduction?.length > 0 && (
            <section>
              <h3>Reproduction</h3>
              <ol className="steps">
                {finding.reproduction.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ol>
            </section>
          )}

          {finding.recommendation && (
            <section className="recommendation">
              <h3>Recommendation</h3>
              <p>{finding.recommendation}</p>
            </section>
          )}
        </div>
      )}
    </article>
  )
}

export default function App() {
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')
  const [expandedId, setExpandedId] = useState(null)

  useEffect(() => {
    fetch('/findings.json')
      .then((res) => {
        if (!res.ok) throw new Error(`Failed to load findings (${res.status})`)
        return res.json()
      })
      .then((data) => {
        setReport(data)
        const firstVuln = data.findings?.find((f) => f.status === 'vulnerable')
        setExpandedId(firstVuln?.id ?? data.findings?.[0]?.id ?? null)
      })
      .catch((err) => setError(err.message))
  }, [])

  const filtered = useMemo(() => {
    if (!report?.findings) return []
    return [...report.findings]
      .filter((f) => (severityFilter === 'all' ? true : f.severity === severityFilter))
      .filter((f) => (statusFilter === 'all' ? true : f.status === statusFilter))
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
  }, [report, severityFilter, statusFilter])

  if (error) {
    return (
      <div className="shell">
        <p className="error">Could not load findings: {error}</p>
        <p className="hint">
          Run <code>npm run sync-findings</code> after scanning, then refresh.
        </p>
      </div>
    )
  }

  if (!report) {
    return (
      <div className="shell">
        <p className="loading">Loading scan report…</p>
      </div>
    )
  }

  const { summary } = report

  return (
    <div className="shell">
      <header className="top">
        <div className="brand-block">
          <p className="brand">SentinelAPI</p>
          <h1>Vulnerability findings</h1>
          <p className="sub">
            Scan of <code>{report.target}</code> · {formatTime(report.scannedAt)}
            {report.openapi?.title ? (
              <>
                {" "}
                · OpenAPI <code>{report.openapi.title}</code>
                {report.openapi.pathCount != null ? ` (${report.openapi.pathCount} paths)` : ""}
              </>
            ) : null}
          </p>
        </div>
        <div className="score">
          <span className="score-label">Issues</span>
          <span className="score-value">{summary.vulnerable}</span>
          <span className="score-meta">
            of {summary.total} checks · {summary.secure} secure
          </span>
        </div>
      </header>

      <section className="summary" aria-label="Severity summary">
        {SEVERITIES.map((sev) => (
          <button
            key={sev}
            type="button"
            className={`stat severity-${sev} ${severityFilter === sev ? 'active' : ''}`}
            onClick={() => setSeverityFilter((prev) => (prev === sev ? 'all' : sev))}
          >
            <span className="stat-count">{summary[sev] ?? 0}</span>
            <span className="stat-label">{sev}</span>
          </button>
        ))}
      </section>

      <div className="toolbar">
        <div className="filters" role="group" aria-label="Status filter">
          {STATUSES.map((status) => (
            <button
              key={status}
              type="button"
              className={statusFilter === status ? 'active' : ''}
              onClick={() => setStatusFilter(status)}
            >
              {status}
            </button>
          ))}
        </div>
        <p className="result-count">
          Showing {filtered.length} finding{filtered.length === 1 ? '' : 's'}
          {severityFilter !== 'all' ? ` · ${severityFilter}` : ''}
        </p>
      </div>

      <div className="findings">
        {filtered.length === 0 ? (
          <p className="empty">No findings match these filters.</p>
        ) : (
          filtered.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              expanded={expandedId === finding.id}
              onToggle={() =>
                setExpandedId((id) => (id === finding.id ? null : finding.id))
              }
            />
          ))
        )}
      </div>
    </div>
  )
}

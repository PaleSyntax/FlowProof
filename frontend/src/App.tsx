import { useCallback, useEffect, useState } from 'react'
import { api } from './api'
import { XeroQualification } from './XeroQualification'
import type {
  AuthPrincipal,
  Incident,
  OperatorReviewCheck,
  OperatorReviewInput,
  Policy,
  RecoveryAttempt,
  RecoveryDecision,
  RecoveryPlan,
  SecurityAuditEvent,
  TimelineEvent,
  FixtureDemoStart,
} from './types'

type View = 'onboarding' | 'overview' | 'incidents' | 'timeline' | 'chaos' | 'policies' | 'admin'

function pretty(value: unknown) {
  return JSON.stringify(value, null, 2)
}

function can(principal: AuthPrincipal, scope: string) {
  return principal.scopes.includes(scope)
}

function Login({ onLogin }: { onLogin: (name: string, password: string) => Promise<void> }) {
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await onLogin(name, password)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Login failed')
    } finally {
      setBusy(false)
    }
  }
  return <main className="login-shell"><section className="login-card"><p className="eyebrow">Outcome assurance for business-critical n8n automations</p><h1>FlowProof</h1><p>Sign in to follow a business entity from workflow execution to independently verified outcome.</p><form onSubmit={(event) => void submit(event)}><label>Username<input value={name} onChange={(event) => setName(event.target.value)} autoComplete="username" /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label><button disabled={busy || !name || !password}>Sign in</button>{error && <p className="error">{error}</p>}</form></section></main>
}

function RecoveryControls({ plan, incidentStatus, principal, onChange, fixtureDemo = false }: { plan: RecoveryPlan; incidentStatus: string; principal: AuthPrincipal; onChange: () => void; fixtureDemo?: boolean }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fixtureReady, setFixtureReady] = useState(false)
  const [attempts, setAttempts] = useState<RecoveryAttempt[]>([])
  const [decisions, setDecisions] = useState<RecoveryDecision[]>([])
  const [review, setReview] = useState<OperatorReviewInput>({
    plan_hash: plan.plan_hash,
    capsule_digest: null,
    evidence_understood: false,
    authoritative_source_understood: false,
    blast_radius_understood: false,
    proposed_action_understood: false,
    reject_path_available: false,
    revoke_path_available: false,
    reconciliation_path_understood: false,
    final_decision: 'observe_only',
    note: null,
  })
  useEffect(() => {
    let active = true
    void Promise.all([api.attempts(plan.id), api.decisions(plan.id)]).then(([attemptResult, decisionResult]) => {
      if (active) { setAttempts(attemptResult.items); setDecisions(decisionResult.items) }
    }).catch(() => { if (active) { setAttempts([]); setDecisions([]) } })
    return () => { active = false }
  }, [plan.id, plan.status])
  const run = async (operation: () => Promise<unknown>) => {
    setBusy(true); setError(null)
    try { await operation(); onChange() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Recovery operation failed') } finally { setBusy(false) }
  }
  const reviewCheck = (key: OperatorReviewCheck) => setReview((current) => ({
    ...current,
    [key]: !current[key],
  }))
  return <section className="recovery"><h3>Safe recovery plan</h3><p><code>{plan.action_type}</code> · status: <strong>{plan.status}</strong></p>
    <p>Provider: <strong>{plan.provider_id}</strong> · {plan.provider_environment} · adapter {plan.adapter_version}</p>
    <p>Contract: <code>{plan.provider_contract_digest}</code></p>
    {plan.approval_expires_at && <p>Approval expires: <time>{new Date(plan.approval_expires_at).toLocaleString()}</time></p>}
    <details><summary>Immutable parameters and guardrails</summary><pre>{pretty({ parameters: plan.parameters, guardrails: plan.guardrails })}</pre></details><div className="actions">
    {plan.status === 'proposed' && can(principal, 'recovery:approve') && <><button disabled={busy} onClick={() => void run(() => api.approve(plan.id, plan.plan_hash, incidentStatus))}>Approve</button><button className="secondary" disabled={busy} onClick={() => void run(() => api.reject(plan.id, plan.plan_hash, incidentStatus, 'operator_rejected'))}>Reject</button></>}
    {plan.status === 'approved' && can(principal, 'recovery:approve') && <button className="secondary" disabled={busy} onClick={() => void run(() => api.revokeApproval(plan.id, plan.plan_hash, incidentStatus, 'operator_withdrew_consent'))}>Revoke approval</button>}
    {fixtureDemo && plan.status === 'approved' && !fixtureReady && <button disabled={busy} onClick={() => void run(async () => { await api.setChaos('normal'); setFixtureReady(true) })}>Prepare healthy fixture for compensation</button>}
    {plan.status === 'approved' && can(principal, 'recovery:execute') && <button disabled={busy || (fixtureDemo && !fixtureReady)} onClick={() => void run(() => api.execute(plan.id))}>Execute one compensation</button>}
    {(plan.status === 'verifying' || plan.status === 'still_failed') && can(principal, 'recovery:verify') && <button disabled={busy} onClick={() => void run(() => api.verify(plan.id))}>{plan.status === 'still_failed' ? 'Recheck outcome' : 'Verify outcome'}</button>}
    {(plan.status === 'needs_attention' || plan.status === 'executing') && can(principal, 'recovery:verify') && <button disabled={busy} onClick={() => void run(() => api.reconcile(plan.id, plan.plan_hash))}>Authoritative reconcile</button>}
    {plan.status === 'still_failed' && <span className="badge">Postcondition still failed</span>}
    {plan.status === 'verified' && <span className="badge resolved">Verified and resolved</span>}
    {(plan.status === 'needs_attention' || plan.status === 'executing') && <span className="badge">Ambiguous outcome: no automatic retry</span>}
  </div>{error && <p className="error">{error}</p>}
    <details><summary>Attempt history ({attempts.length})</summary><pre>{pretty(attempts)}</pre></details>
    <details><summary>Decision history ({decisions.length})</summary><pre>{pretty(decisions)}</pre></details>
    <details><summary>Evidence capsule</summary><p>Set exact <code>FLOWPROOF_GIT_COMMIT</code> and <code>FLOWPROOF_GIT_TREE</code>, then export: <code>python -m flowproof.evidence export --incident-id &lt;incident-id&gt; --output evidence.zip</code></p><p>Record the returned <code>review_subject_sha256</code> below. After review, export again and verify with independently trusted values: <code>python -m flowproof.evidence verify --input evidence.zip --expected-bundle-sha256 &lt;root&gt; --expected-git-commit &lt;commit&gt; --expected-git-tree &lt;tree&gt;</code></p></details>
    {principal.kind === 'human' && can(principal, 'recovery:approve') && <details><summary>Operator contestability review</summary>
      {([
        ['evidence_understood', 'Evidence understood'],
        ['authoritative_source_understood', 'Authoritative source understood'],
        ['blast_radius_understood', 'Blast radius understood'],
        ['proposed_action_understood', 'Proposed action understood'],
        ['reject_path_available', 'Reject path available'],
        ['revoke_path_available', 'Revoke path available before dispatch'],
        ['reconciliation_path_understood', 'Rollback/reconciliation path understood'],
      ] as Array<[OperatorReviewCheck, string]>).map(([key, label]) => <label key={key}><input type="checkbox" checked={review[key]} onChange={() => reviewCheck(key)} />{label}</label>)}
      <label>Reviewed evidence digest<input value={review.capsule_digest ?? ''} pattern="[0-9a-f]{64}" maxLength={64} onChange={(event) => setReview((current) => ({ ...current, capsule_digest: event.target.value || null }))} /></label>
      <label>Final decision<select value={review.final_decision} onChange={(event) => setReview((current) => ({ ...current, final_decision: event.target.value as OperatorReviewInput['final_decision'] }))}><option value="observe_only">observe only</option><option value="approve">approve</option><option value="reject">reject</option><option value="revoke_approval">revoke approval</option></select></label>
      <button disabled={busy} onClick={() => void run(() => api.operatorReview(plan.id, { ...review, plan_hash: plan.plan_hash }))}>Record review</button>
    </details>}
  </section>
}

function IncidentDetail({ incident, principal, onChange, fixtureDemo = false }: { incident: Incident; principal: AuthPrincipal; onChange: () => void; fixtureDemo?: boolean }) {
  return <article className="detail"><div className="detail-heading"><div><p className="eyebrow">{incident.entity_type} · {incident.entity_id}</p><h2>{incident.summary}</h2><p>Invariant <code>{incident.invariant_id}</code> · correlation <code>{incident.correlation_id}</code></p></div><span className={`badge ${incident.status}`}>{incident.status}</span></div><div className="evidence-grid"><section><h3>Evidence</h3><pre>{pretty(incident.evidence)}</pre></section><section><h3>Technical provenance</h3><p>Evidence references immutable event IDs and an independent verifier observation.</p></section></div>{incident.recovery_plan ? <RecoveryControls plan={incident.recovery_plan} incidentStatus={incident.status} principal={principal} onChange={onChange} fixtureDemo={fixtureDemo} /> : <p className="muted">No allowlisted recovery exists for this incident.</p>}</article>
}

function GuidedOnboarding({ principal, onComplete }: { principal: AuthPrincipal; onComplete: () => void }) {
  const [demo, setDemo] = useState<FixtureDemoStart | null>(null)
  const [incident, setIncident] = useState<Incident | null>(null)
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refreshDemo = async (current = demo) => {
    if (!current) return
    const [nextIncident, nextTimeline] = await Promise.all([
      api.incident(current.incident_id),
      api.timeline(current.entity_type, current.entity_id),
    ])
    setIncident(nextIncident)
    setTimeline(nextTimeline.items)
  }
  const startDemo = async () => {
    setBusy(true); setError(null)
    try {
      const started = await api.startFixtureDemo()
      setDemo(started)
      await refreshDemo(started)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Safe demo could not start')
    } finally { setBusy(false) }
  }
  const completed = incident?.status === 'resolved' && incident.recovery_plan?.status === 'verified'

  return <section className="onboarding"><div className="onboarding-hero"><div><p className="eyebrow">Guided first value</p><h2>Outcome assurance for business-critical n8n automations</h2><p>n8n can finish green while the business result is still missing. FlowProof links the entity across executions, rereads the authoritative system, applies deterministic invariants, and preserves causal evidence.</p></div><span className="fixture-label">TEST_FIXTURE_ONLY</span></div>
    <div className="journey-grid">
      <article><span>01</span><h3>Workflow boundary</h3><p>This safe path simulates an accepted invoice registration step. It does not claim a real n8n execution.</p></article>
      <article><span>02</span><h3>Protected outcome</h3><p>Exactly one invoice must exist in authoritative accounting with the validated amount and currency.</p></article>
      <article><span>03</span><h3>Correlation</h3><p>FlowProof creates one invoice ID and correlation key automatically—no token or secret copying.</p></article>
      <article><span>04</span><h3>Independent verifier</h3><p>Mock Accounting is reread independently and is clearly bounded to this fixture.</p></article>
    </div>
    <XeroQualification canWrite={can(principal, 'evaluations:write')} />
    {!demo && <div className="demo-callout"><div><h3>Run the false-200 golden path</h3><p>The workflow-facing call returns accepted, but the fixture persists nothing. FlowProof must catch the missing outcome and require a human before one narrow compensation.</p></div><button disabled={busy || !can(principal, 'chaos:write')} onClick={() => void startDemo()}>{busy ? 'Creating evidence…' : 'Start safe demo'}</button></div>}
    {error && <div className="next-action error"><strong>Demo unavailable.</strong><span>{error}</span><span>Next action: verify that the local appliance is healthy, then try once more.</span></div>}
    {demo && incident && <><div className="truth-comparison"><article className="transport-result"><p className="eyebrow">Execution signal</p><strong>Accepted</strong><p>Fixture transport returned success.</p><small>Real n8n execution proven: no</small></article><article className="outcome-result"><p className="eyebrow">Business outcome</p><strong>Missing</strong><p>Authoritative reread found no invoice.</p><small>Invariant: external_invoice_exists</small></article><article className="proof-result"><p className="eyebrow">FlowProof decision</p><strong>Incident</strong><p>Recovery is proposed, never silently replayed.</p><small>{demo.incident_id.slice(0, 8)}…</small></article></div>
      <section className="timeline-panel"><div><p className="eyebrow">Causal evidence</p><h3>One entity timeline</h3><p><code>{demo.entity_id}</code> · correlation <code>{demo.correlation_id}</code></p></div><ol className="timeline compact">{timeline.map((event) => <li key={event.id}><strong>{event.event_type}</strong><time>{new Date(event.occurred_at).toLocaleString()}</time></li>)}</ol></section>
      <IncidentDetail incident={incident} principal={principal} fixtureDemo onChange={() => void refreshDemo()} />
      <div className="demo-callout completion"><div><h3>{completed ? 'Fixture outcome verified' : 'Human gate still active'}</h3><p>{completed ? 'One approved compensation was independently reread and the incident resolved.' : 'Review the evidence above, approve or reject explicitly, then execute and verify only if approved.'}</p></div>{completed && <button onClick={onComplete}>Finish guided setup</button>}</div>
      <aside className="next-action"><strong>Next: connect an existing n8n workflow</strong><span>Open the Windows controller and enter the n8n URL, an owner-created n8n API key, and the FlowProof URL reachable by that instance. FlowProof provisions its fixed least-privilege credential and four workflow templates directly into n8n—no manual FlowProof token copying, and the n8n API key is not stored. This path is locally qualified on n8n 2.30.5; real-provider observation still requires owner-authorized access.</span></aside>
    </>}
  </section>
}

function Admin({ principals, audit, onRefresh }: { principals: AuthPrincipal[]; audit: SecurityAuditEvent[]; onRefresh: () => Promise<void> }) {
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('viewer')
  const [serviceName, setServiceName] = useState('')
  const [serviceScopes, setServiceScopes] = useState('events:write')
  const [credentialPrincipal, setCredentialPrincipal] = useState('')
  const [credentialScopes, setCredentialScopes] = useState('events:write')
  const [credentialLabel, setCredentialLabel] = useState('')
  const [credentialTtl, setCredentialTtl] = useState('86400')
  const [credentials, setCredentials] = useState<Array<Record<string, unknown>>>([])
  const [oneTimeToken, setOneTimeToken] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const scopes = (value: string) => value.split(',').map((item) => item.trim()).filter(Boolean)
  const action = async (operation: () => Promise<unknown>) => {
    setError(null)
    try { await operation(); await onRefresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'Identity operation failed') }
  }
  const loadCredentials = async (principalId: string) => {
    setCredentialPrincipal(principalId)
    setOneTimeToken(null)
    try { setCredentials((await api.credentials(principalId)).items) } catch (cause) { setError(cause instanceof Error ? cause.message : 'Credential list unavailable') }
  }
  const issue = async () => action(async () => {
    if (!credentialPrincipal) throw new Error('Select a service account')
    const issued = await api.issueCredential(credentialPrincipal, scopes(credentialScopes), Number(credentialTtl), credentialLabel)
    setOneTimeToken(issued.token)
    setCredentials((await api.credentials(credentialPrincipal)).items)
  })
  const rotate = async (credentialId: string) => action(async () => {
    const issued = await api.rotateCredential(credentialId, Number(credentialTtl))
    setOneTimeToken(issued.token)
    if (credentialPrincipal) setCredentials((await api.credentials(credentialPrincipal)).items)
  })

  return <section><h2>Identity administration</h2><p className="muted">Administrative actions require the current human admin session and CSRF token.</p>{error && <p className="error">{error}</p>}
    {oneTimeToken && <section className="recovery"><h3>One-time API token</h3><p><strong>This token will not be shown again.</strong></p><code>{oneTimeToken}</code><div className="actions"><button className="secondary" onClick={() => setOneTimeToken(null)}>Close token</button></div></section>}
    <section className="recovery"><h3>Create human</h3><label>Name<input value={name} onChange={(event) => setName(event.target.value)} /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /></label><label>Role<select value={role} onChange={(event) => setRole(event.target.value)}><option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option></select></label><button onClick={() => void action(async () => { await api.createHuman(name, password, role); setName(''); setPassword('') })} disabled={!name || password.length < 12}>Create human</button></section>
    <section className="recovery"><h3>Create service account</h3><label>Name<input value={serviceName} onChange={(event) => setServiceName(event.target.value)} /></label><label>Allowed scopes (comma separated)<input value={serviceScopes} onChange={(event) => setServiceScopes(event.target.value)} /></label><button onClick={() => void action(async () => { await api.createServiceAccount(serviceName, scopes(serviceScopes)); setServiceName('') })} disabled={!serviceName}>Create service account</button></section>
    <section><h3>Principals</h3>{principals.map((item) => <article className="recovery" key={item.id}><strong>{item.name}</strong> <span className="muted">{item.kind} {item.role ?? ''}</span><p>Allowed scopes: {(item.allowed_scopes ?? item.scopes).join(', ') || 'none'}</p><div className="actions">{item.kind === 'human' && <select aria-label={`Role for ${item.name}`} value={item.role ?? 'viewer'} onChange={(event) => void action(() => api.changeRole(item.id, event.target.value))}><option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option></select>}{item.kind === 'service' && <button className="secondary" onClick={() => void loadCredentials(item.id)}>Credentials</button>}<button className="secondary" onClick={() => void action(() => api.disablePrincipal(item.id))} disabled={Boolean(item.disabled_at)}>Disable</button></div></article>)}</section>
    {credentialPrincipal && <section className="recovery"><h3>Credential lifecycle</h3><label>Credential scopes (subset of service envelope)<input value={credentialScopes} onChange={(event) => setCredentialScopes(event.target.value)} /></label><label>TTL seconds<input type="number" min="1" value={credentialTtl} onChange={(event) => setCredentialTtl(event.target.value)} /></label><label>Label<input value={credentialLabel} onChange={(event) => setCredentialLabel(event.target.value)} /></label><button onClick={() => void issue()}>Issue credential</button><pre>{pretty(credentials)}</pre>{credentials.map((item) => <div className="actions" key={String(item.id)}><code>{String(item.token_prefix)}</code><button className="secondary" onClick={() => void rotate(String(item.id))} disabled={Boolean(item.revoked_at)}>Rotate</button><button className="secondary" onClick={() => void action(async () => { await api.revokeCredential(String(item.id)); if (credentialPrincipal) setCredentials((await api.credentials(credentialPrincipal)).items) })} disabled={Boolean(item.revoked_at)}>Revoke</button></div>)}</section>}
    <h3>Security audit</h3><pre>{pretty(audit)}</pre></section>
}

export default function App() {
  const [view, setView] = useState<View>('onboarding')
  const [principal, setPrincipal] = useState<AuthPrincipal | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [blastRadius, setBlastRadius] = useState<Array<Record<string, unknown>>>([])
  const [selected, setSelected] = useState<Incident | null>(null)
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [principals, setPrincipals] = useState<AuthPrincipal[]>([])
  const [audit, setAudit] = useState<SecurityAuditEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const clearSessionState = useCallback((message: string | null = null) => {
    api.clearAuth()
    setPrincipal(null)
    setSelected(null)
    setTimeline([])
    setPrincipals([])
    setAudit([])
    setView('onboarding')
    setError(message)
  }, [])
  useEffect(() => api.onUnauthorized(() => {
    clearSessionState('Your session has expired. Please sign in again.')
  }), [clearSessionState])

  const refresh = useCallback(async () => {
    const [incidentResult, policyResult, blastResult] = await Promise.all([api.incidents(), api.policies(), api.blastRadius()])
    setIncidents(incidentResult.items); setPolicies(policyResult.items); setBlastRadius(blastResult.items)
  }, [])
  const restore = useCallback(async () => {
    try { const auth = await api.me(); setPrincipal(auth.principal); await refresh(); setView(window.localStorage.getItem('flowproof:onboarding:v1') === 'complete' ? 'overview' : 'onboarding') } catch { clearSessionState(null) } finally { setLoading(false) }
  }, [clearSessionState, refresh])
  useEffect(() => {
    const restoreTimer = window.setTimeout(() => { void restore() }, 0)
    return () => window.clearTimeout(restoreTimer)
  }, [restore])

  const signIn = async (name: string, password: string) => {
    const auth = await api.login(name, password); setPrincipal(auth.principal); await refresh(); setView(window.localStorage.getItem('flowproof:onboarding:v1') === 'complete' ? 'overview' : 'onboarding'); setError(null)
  }
  const signOut = async () => { try { await api.logout() } finally { clearSessionState(null) } }
  const refreshWithError = async () => { try { setError(null); await refresh() } catch (cause) { setError(cause instanceof Error ? cause.message : 'API unavailable') } }
  const loadAdmin = async () => { try { const [principalResult, auditResult] = await Promise.all([api.principals(), api.audit()]); setPrincipals(principalResult.items); setAudit(auditResult.items); setView('admin') } catch (cause) { setError(cause instanceof Error ? cause.message : 'Admin data unavailable') } }

  if (loading) return <main><p className="muted">Restoring secure session…</p></main>
  if (!principal) return <Login onLogin={signIn} />
  const views: Array<[View, string]> = [
    ['onboarding', 'Guided setup'], ['overview', 'Overview'], ['incidents', 'Incidents'], ['timeline', 'Entity timeline'], ['policies', 'Policies'],
    ...(can(principal, 'chaos:write') ? [['chaos', 'Chaos Lab'] as [View, string]] : []),
    ...(principal.kind === 'human' && principal.role === 'admin' ? [['admin', 'Admin'] as [View, string]] : []),
  ]
  const chooseIncident = async (incident: Incident, target: View) => { setSelected(incident); setView(target); if (target === 'timeline') setTimeline((await api.timeline(incident.entity_type, incident.entity_id)).items); else setSelected(await api.incident(incident.id)) }

  return <main><header><div><p className="eyebrow">Outcome assurance for business-critical n8n automations</p><h1>FlowProof</h1><p className="muted">{principal.name} · {principal.role ?? principal.kind}</p></div><div className="actions"><button className="secondary" onClick={() => void refreshWithError()}>Refresh</button><button className="secondary" onClick={() => void signOut()}>Sign out</button></div></header><nav>{views.map(([key, label]) => <button key={key} className={view === key ? 'active' : ''} onClick={() => key === 'admin' ? void loadAdmin() : setView(key)}>{label}</button>)}</nav>{error && <p className="error">{error}</p>}
    {view === 'onboarding' && <GuidedOnboarding principal={principal} onComplete={() => { window.localStorage.setItem('flowproof:onboarding:v1', 'complete'); setView('overview') }} />}
    {view === 'overview' && <section><h2>Outcome overview</h2><div className="metrics"><div><strong>{incidents.filter((item) => item.status !== 'resolved').length}</strong><span>open incidents</span></div><div><strong>{blastRadius.length}</strong><span>affected correlations</span></div><div><strong>{policies.length}</strong><span>active policies</span></div></div><h3>Current blast radius</h3><pre>{pretty(blastRadius)}</pre></section>}
    {view === 'incidents' && <section><h2>Incidents</h2><div className="incident-layout"><div className="incident-list">{incidents.map((item) => <button className="incident-row" key={item.id} onClick={() => void chooseIncident(item, 'incidents')}><span className={`badge ${item.status}`}>{item.status}</span><strong>{item.summary}</strong><small>{item.entity_id} · {item.invariant_id}</small></button>)}</div>{selected && <IncidentDetail incident={selected} principal={principal} onChange={() => void refreshWithError()} />}</div></section>}
    {view === 'timeline' && <section><h2>Entity timeline</h2>{selected ? <><p>{selected.entity_type} <code>{selected.entity_id}</code></p><button onClick={() => void chooseIncident(selected, 'timeline')}>Load timeline</button><ol className="timeline">{timeline.map((event) => <li key={event.id}><strong>{event.event_type}</strong><time>{new Date(event.occurred_at).toLocaleString()}</time><pre>{pretty(event.payload)}</pre></li>)}</ol></> : <p className="muted">Select an incident to inspect provenance.</p>}</section>}
    {view === 'policies' && <section><h2>Active policies</h2>{policies.map((policy) => <article className="policy" key={policy.id}><h3>{policy.name} <small>v{policy.version}</small></h3><p>Definition hash: <code>{policy.definition_hash}</code></p></article>)}</section>}
    {view === 'chaos' && can(principal, 'chaos:write') && <section><h2>Chaos Lab</h2>{['normal', 'false_200', 'timeout', 'delayed_write', 'amount_mismatch', 'partial_success'].map((mode) => <button key={mode} onClick={() => void api.setChaos(mode).then(refreshWithError).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Chaos change failed'))}>{mode}</button>)}</section>}
    {view === 'admin' && principal.kind === 'human' && principal.role === 'admin' && <Admin principals={principals} audit={audit} onRefresh={loadAdmin} />}
  </main>
}

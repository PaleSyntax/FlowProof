import { useEffect, useState } from 'react'
import { ApiError, api } from './api'
import type { XeroConnectionStatus, XeroQualificationEvidence } from './types'

function evidenceFileName(evidence: XeroQualificationEvidence) {
  return `flowproof-xero-observe-only-${evidence.session_id}.json`
}

export function XeroQualification({ canWrite }: { canWrite: boolean }) {
  const [available, setAvailable] = useState<boolean | null>(null)
  const [status, setStatus] = useState<XeroConnectionStatus | null>(null)
  const [clientId, setClientId] = useState('')
  const [authorizationUrl, setAuthorizationUrl] = useState<string | null>(null)
  const [invoiceId, setInvoiceId] = useState('')
  const [expectedAmount, setExpectedAmount] = useState('')
  const [currency, setCurrency] = useState('USD')
  const [confirmed, setConfirmed] = useState(false)
  const [evidence, setEvidence] = useState<XeroQualificationEvidence | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refreshStatus = async () => {
    try {
      const next = await api.xeroStatus()
      setStatus(next)
      setAvailable(true)
      if (next.connected) setAuthorizationUrl(null)
    } catch (cause) {
      if (cause instanceof ApiError && cause.status === 404) {
        setAvailable(false)
        return
      }
      setError(cause instanceof Error ? cause.message : 'Xero status is unavailable')
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => { void refreshStatus() }, 0)
    return () => window.clearTimeout(timer)
  }, [])

  useEffect(() => {
    if (!status?.pending_authorization) return
    const timer = window.setInterval(() => { void refreshStatus() }, 2000)
    return () => window.clearInterval(timer)
  }, [status?.pending_authorization])

  const connect = async () => {
    const popup = window.open('about:blank', 'flowproof-xero-pkce', 'popup,width=720,height=760')
    setBusy(true)
    setError(null)
    try {
      const started = await api.startXeroPkce(clientId.trim())
      setAuthorizationUrl(started.authorization_url)
      setStatus((current) => current ? { ...current, pending_authorization: true } : current)
      if (popup) {
        popup.opener = null
        popup.location.assign(started.authorization_url)
      }
    } catch (cause) {
      popup?.close()
      setError(cause instanceof Error ? cause.message : 'Xero authorization could not start')
    } finally {
      setBusy(false)
    }
  }

  const disconnect = async () => {
    setBusy(true)
    setError(null)
    try {
      setStatus(await api.disconnectXero())
      setEvidence(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Xero could not be disconnected')
    } finally {
      setBusy(false)
    }
  }

  const qualify = async (event: React.FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    setEvidence(null)
    try {
      setEvidence(await api.qualifyXeroInvoice({
        invoice_id: invoiceId.trim(),
        expected_exists: true,
        expected_amount: Number(expectedAmount),
        currency,
        provider_identity_confirmed: confirmed,
        entity_confirmed: confirmed,
        evidence_bounded: confirmed,
        no_mutation_confirmed: confirmed,
      }))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Observe-only qualification failed')
    } finally {
      setBusy(false)
    }
  }

  const downloadEvidence = () => {
    if (!evidence) return
    const url = URL.createObjectURL(new Blob([JSON.stringify(evidence, null, 2)], { type: 'application/json' }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = evidenceFileName(evidence)
    anchor.click()
    URL.revokeObjectURL(url)
  }

  if (available === false) return null

  return <section className="xero-qualification" aria-labelledby="xero-heading">
    <div className="provider-heading">
      <div><p className="eyebrow">Optional real-provider proof</p><h3 id="xero-heading">Observe one invoice in Xero Demo Company</h3></div>
      <span className={`badge ${status?.connected ? 'verified' : ''}`}>{status?.connected ? 'Demo connected' : 'Not connected'}</span>
    </div>
    <p>This separate qualification reads one exact invoice and never writes to Xero. The access token stays in API process memory, expires without refresh, and is never copied into FlowProof.</p>
    {!status?.connected ? <div className="provider-form">
      <label>Xero app Client ID (public, not a secret)<input value={clientId} minLength={8} maxLength={128} autoComplete="off" onChange={(event) => setClientId(event.target.value)} placeholder="Your Xero app Client ID" /></label>
      <div className="actions"><button disabled={busy || !canWrite || clientId.trim().length < 8} onClick={() => void connect()}>{busy ? 'Starting consent…' : 'Connect Xero Demo'}</button><button className="secondary" disabled={busy} onClick={() => void refreshStatus()}>Check connection</button></div>
      {status?.pending_authorization && <p className="muted">Consent is open in a separate window. Complete it, then return here.</p>}
      {authorizationUrl && <p className="muted">Popup blocked? <a href={authorizationUrl} target="_blank" rel="noreferrer">Continue to Xero</a>.</p>}
    </div> : <form className="provider-form" onSubmit={(event) => void qualify(event)}>
      <div className="provider-fields"><label>Exact invoice ID or number<input required value={invoiceId} maxLength={255} onChange={(event) => setInvoiceId(event.target.value)} placeholder="INV-0001" /></label><label>Expected total<input required type="number" min="0" step="0.01" value={expectedAmount} onChange={(event) => setExpectedAmount(event.target.value)} /></label><label>Currency<input required value={currency} pattern="[A-Z]{3}" maxLength={3} onChange={(event) => setCurrency(event.target.value.toUpperCase())} /></label></div>
      <label className="provider-confirmation"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I confirm the Demo Company, exact safe invoice, bounded evidence, and zero provider mutation.</label>
      <div className="actions"><button disabled={busy || !canWrite || !confirmed || !invoiceId.trim() || expectedAmount === ''}>{busy ? 'Reading invoice…' : 'Run observe-only check'}</button><button type="button" className="secondary" disabled={busy} onClick={() => void disconnect()}>Discard connection</button></div>
    </form>}
    {error && <p className="error">{error}</p>}
    {evidence && <div className="qualification-result"><p className="eyebrow">Machine-readable evidence</p><h3>Invariant {evidence.observation.invariant_result.toLowerCase()}</h3><p>{evidence.observation.classification} · provider mutations: {evidence.safety.provider_mutation_count}</p><button type="button" onClick={downloadEvidence}>Save evidence JSON</button></div>}
  </section>
}

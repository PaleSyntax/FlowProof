import type {
  AuthPrincipal,
  ApiCredential,
  Incident,
  IssuedCredential,
  Policy,
  OperatorReviewInput,
  RecoveryAttempt,
  RecoveryDecision,
  RecoveryPlan,
  SecurityAuditEvent,
  TimelineEvent,
  FixtureDemoStart,
  XeroConnectionStatus,
  XeroPkceStart,
  XeroQualificationEvidence,
} from './types'

const pageOrigin = new URL(window.location.href)
pageOrigin.port = '8000'
pageOrigin.pathname = '/api/v1'
pageOrigin.search = ''
pageOrigin.hash = ''
const base = import.meta.env.VITE_FLOWPROOF_API_URL ?? pageOrigin.toString().replace(/\/$/, '')
let csrfToken: string | null = null
let onUnauthorized: (() => void) | null = null

type AuthResponse = { principal: AuthPrincipal; csrf_token: string | null }

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
    this.name = 'ApiError'
  }
}

function clearAuth() {
  csrfToken = null
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (init.method && init.method !== 'GET' && csrfToken) headers.set('X-CSRF-Token', csrfToken)
  const response = await fetch(`${base}${path}`, { ...init, headers, credentials: 'include' })
  if (!response.ok) {
    const error = new ApiError((await response.json().catch(() => null))?.detail ?? response.statusText, response.status)
    if (response.status === 401) {
      clearAuth()
      onUnauthorized?.()
    }
    throw error
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

function retainCsrf(response: AuthResponse): AuthResponse {
  csrfToken = response.csrf_token
  return response
}

export const api = {
  onUnauthorized(handler: () => void) {
    onUnauthorized = handler
    return () => { if (onUnauthorized === handler) onUnauthorized = null }
  },
  clearAuth,
  login: (name: string, password: string) =>
    request<AuthResponse>('/auth/login', { method: 'POST', body: JSON.stringify({ name, password }) }).then(retainCsrf),
  me: () => request<AuthResponse>('/auth/me').then(retainCsrf),
  logout: () => request<void>('/auth/logout', { method: 'POST' }).finally(clearAuth),
  incidents: () => request<{ items: Incident[] }>('/incidents'),
  incident: (id: string) => request<Incident>(`/incidents/${id}`),
  timeline: (entityType: string, entityId: string) =>
    request<{ items: TimelineEvent[] }>(`/entities/${entityType}/${encodeURIComponent(entityId)}/timeline`),
  policies: () => request<{ items: Policy[] }>('/policies'),
  blastRadius: () => request<{ items: Array<Record<string, unknown>> }>('/blast-radius'),
  setChaos: (mode: string) => request('/chaos/mode', { method: 'POST', body: JSON.stringify({ mode }) }),
  startFixtureDemo: () => request<FixtureDemoStart>('/demo/false-200/start', { method: 'POST' }),
  xeroStatus: () => request<XeroConnectionStatus>('/provider-connections/xero/status'),
  startXeroPkce: (clientId: string) => request<XeroPkceStart>('/provider-connections/xero/pkce/start', {
    method: 'POST', body: JSON.stringify({ client_id: clientId }),
  }),
  disconnectXero: () => request<XeroConnectionStatus>('/provider-connections/xero/disconnect', { method: 'POST' }),
  qualifyXeroInvoice: (input: {
    invoice_id: string
    expected_exists: boolean
    expected_amount: number
    currency: string
    provider_identity_confirmed: boolean
    entity_confirmed: boolean
    evidence_bounded: boolean
    no_mutation_confirmed: boolean
  }) => request<XeroQualificationEvidence>('/provider-connections/xero/qualify-invoice', {
    method: 'POST', body: JSON.stringify(input),
  }),
  approve: (id: string, planHash: string, incidentStatus: string) =>
    request<RecoveryPlan>(`/recovery-plans/${id}/approve`, {
      method: 'POST', body: JSON.stringify({ plan_hash: planHash, incident_status: incidentStatus }),
    }),
  reject: (id: string, planHash: string, incidentStatus: string, reasonCode: string) =>
    request<RecoveryPlan>(`/recovery-plans/${id}/reject`, {
      method: 'POST', body: JSON.stringify({ plan_hash: planHash, incident_status: incidentStatus, reason_code: reasonCode }),
    }),
  revokeApproval: (id: string, planHash: string, incidentStatus: string, reasonCode: string) =>
    request<RecoveryPlan>(`/recovery-plans/${id}/revoke-approval`, {
      method: 'POST', body: JSON.stringify({ plan_hash: planHash, incident_status: incidentStatus, reason_code: reasonCode }),
    }),
  execute: (id: string) => request<RecoveryPlan>(`/recovery-plans/${id}/execute`, { method: 'POST' }),
  verify: (id: string) => request<RecoveryPlan>(`/recovery-plans/${id}/verify`, { method: 'POST' }),
  reconcile: (id: string, planHash: string) => request<RecoveryPlan>(`/recovery-plans/${id}/reconcile`, {
    method: 'POST', body: JSON.stringify({ plan_hash: planHash }),
  }),
  attempts: (id: string) => request<{ items: RecoveryAttempt[] }>(`/recovery-plans/${id}/attempts`),
  decisions: (id: string) => request<{ items: RecoveryDecision[] }>(`/recovery-plans/${id}/decisions`),
  operatorReview: (id: string, review: OperatorReviewInput) => request<Record<string, unknown>>(
    `/recovery-plans/${id}/operator-review`, { method: 'POST', body: JSON.stringify(review) },
  ),
  principals: () => request<{ items: AuthPrincipal[] }>('/identity/principals'),
  createHuman: (name: string, password: string, role: string) =>
    request<AuthPrincipal>('/identity/humans', { method: 'POST', body: JSON.stringify({ name, password, role }) }),
  createServiceAccount: (name: string, scopes: string[]) =>
    request<AuthPrincipal>('/identity/service-accounts', { method: 'POST', body: JSON.stringify({ name, scopes }) }),
  changeRole: (id: string, role: string) =>
    request<AuthPrincipal>(`/identity/principals/${id}/role`, { method: 'POST', body: JSON.stringify({ role }) }),
  disablePrincipal: (id: string) => request<void>(`/identity/principals/${id}/disable`, { method: 'POST' }),
  credentials: (principalId: string) => request<{ items: ApiCredential[] }>(`/identity/principals/${principalId}/credentials`),
  issueCredential: (principalId: string, scopes: string[], expiresInSeconds: number, label: string) =>
    request<IssuedCredential>(`/identity/principals/${principalId}/credentials`, {
      method: 'POST', body: JSON.stringify({ scopes, expires_in_seconds: expiresInSeconds, label }),
    }),
  rotateCredential: (credentialId: string, expiresInSeconds?: number) =>
    request<IssuedCredential>(`/identity/credentials/${credentialId}/rotate`, {
      method: 'POST', body: JSON.stringify(expiresInSeconds ? { expires_in_seconds: expiresInSeconds } : {}),
    }),
  revokeCredential: (credentialId: string) => request<void>(`/identity/credentials/${credentialId}/revoke`, { method: 'POST' }),
  audit: () => request<{ items: SecurityAuditEvent[] }>('/security/audit'),
}

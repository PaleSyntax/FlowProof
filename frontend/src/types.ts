export type RecoveryPlanStatus =
  | 'proposed'
  | 'approved'
  | 'executing'
  | 'verifying'
  | 'still_failed'
  | 'verified'
  | 'rejected'
  | 'failed'
  | 'needs_attention'
  | 'superseded'

export type RecoveryAttemptState =
  | 'PREPARED'
  | 'DISPATCHING'
  | 'ACCEPTED'
  | 'PRE_ACCEPTANCE_FAILED'
  | 'OUTCOME_UNKNOWN'
  | 'RECONCILING'
  | 'RECONCILED_EFFECT_PRESENT'
  | 'RECONCILED_EFFECT_ABSENT'
  | 'RECONCILED_CONFLICT'
  | 'NEEDS_ATTENTION'
  | 'VERIFYING'
  | 'VERIFIED'
  | 'STILL_FAILED'
  | 'SUPERSEDED_EXTERNAL_RESOLUTION'

export type RecoveryTransportState =
  | 'OUTCOME_UNRECORDED'
  | 'DISPATCHING'
  | 'ACCEPTED'
  | 'OUTCOME_UNKNOWN'
  | 'PRE_ACCEPTANCE_FAILED'
  | 'RECONCILING'
  | 'EFFECT_PRESENT'
  | 'EFFECT_ABSENT'
  | 'CONFLICT'

export type RecoveryTransportInvocation = {
  id: string
  recovery_attempt_id: string
  recovery_plan_id: string
  approval_decision_id: string
  invocation_ordinal: number
  request_digest: string
  reserved_at: string
  state: RecoveryTransportState
  dispatch_owner: string | null
  // Committed JSON Schema requires an integer >= 1; the database default is 1.
  dispatch_generation: number
  dispatch_started_at: string | null
  dispatch_lease_expires_at: string | null
  abandoned_at: string | null
  abandoned_by: string | null
  abandonment_reason: string | null
  reconciliation_owner: string | null
  reconciliation_generation: number
  reconciliation_started_at: string | null
  reconciliation_lease_expires_at: string | null
  reconciliation_abandoned_at: string | null
  outcome_classification: string | null
  outcome_observed_at: string | null
  provider_operation_reference: string | null
  retry_after_seconds: number | null
  safe_outcome: Record<string, unknown>
  completed_at: string | null
  lock_version: number
}

export type RecoveryPlan = {
  id: string
  incident_id: string
  action_type: string
  parameters: Record<string, unknown>
  idempotency_key: string
  risk_level: string
  requires_approval: boolean
  status: RecoveryPlanStatus
  plan_hash: string
  provider_id: string
  provider_environment: string
  adapter_version: string
  provider_contract_digest: string
  provider_contract_snapshot: Record<string, unknown>
  guardrails: Record<string, unknown>
  approved_by: string | null
  approval_context: Record<string, unknown>
  approved_at: string | null
  approval_expires_at: string | null
  executed_at: string | null
  verified_at: string | null
  result: Record<string, unknown>
}

export type RecoveryAttempt = {
  id: string
  recovery_plan_id: string
  incident_id: string
  approval_decision_id: string
  active_transport_invocation_id: string | null
  attempt_ordinal: number
  state: RecoveryAttemptState
  outcome_classification: string | null
  semantic_attempt_count: number
  transport_invocation_count: number
  retry_permitted: boolean
  retry_reason: string | null
  provider_operation_reference: string | null
  safe_result: Record<string, unknown>
  created_at: string
  updated_at: string
  accepted_at: string | null
  reconciled_at: string | null
  lock_version: number
  transport_invocations: RecoveryTransportInvocation[]
}

export type RecoveryDecisionAction =
  | 'approve'
  | 'reject'
  | 'revoke_approval'
  | 'approval_expired'
  | 'approval_invalidated'
  | 'retry_reapproval_required'
  | 'prepared_reapproval_required'
  | 'plan_binding_superseded'
  | 'external_resolution'

export type RecoveryDecision = {
  id: string
  action: RecoveryDecisionAction
  decision_kind: 'human' | 'system'
  actor_display_name: string
  reason_code: string
  previous_plan_state: string
  resulting_plan_state: string
  previous_incident_state: string
  resulting_incident_state: string
  decided_at: string
}

export type OperatorReviewInput = {
  plan_hash: string
  capsule_digest: string | null
  evidence_understood: boolean
  authoritative_source_understood: boolean
  blast_radius_understood: boolean
  proposed_action_understood: boolean
  reject_path_available: boolean
  revoke_path_available: boolean
  reconciliation_path_understood: boolean
  final_decision: 'approve' | 'reject' | 'revoke_approval' | 'observe_only'
  note: string | null
}

export type OperatorReviewCheck =
  | 'evidence_understood'
  | 'authoritative_source_understood'
  | 'blast_radius_understood'
  | 'proposed_action_understood'
  | 'reject_path_available'
  | 'revoke_path_available'
  | 'reconciliation_path_understood'

export type Incident = {
  id: string
  correlation_id: string
  entity_type: string
  entity_id: string
  invariant_id: string
  severity: string
  status: string
  summary: string
  evidence: Record<string, unknown>
  opened_at: string
  resolved_at: string | null
  recovery_plan: RecoveryPlan | null
}

export type TimelineEvent = {
  id: string
  correlation_id: string
  event_type: string
  occurred_at: string
  source: Record<string, string | null>
  payload: Record<string, unknown>
}

export type Policy = {
  id: string
  name: string
  version: string
  entity_type: string
  definition_hash: string
  definition: {
    invariants: Array<{
      id: string
      type: string
      severity: string
      description?: string
    }>
  }
}

export type AuthPrincipal = {
  id: string
  name: string
  kind: 'human' | 'service'
  role: 'viewer' | 'operator' | 'admin' | null
  scopes: string[]
  allowed_scopes?: string[]
  disabled_at?: string | null
  last_successful_login_at?: string | null
}

export type ApiCredential = {
  id: string
  token_prefix: string
  scopes: string[]
  credential_type: string
  label: string | null
  created_at: string
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
}

export type IssuedCredential = {
  credential_id: string
  token_prefix: string
  scopes: string[]
  expires_at: string
  token: string
}

export type SecurityAuditEvent = {
  id: string
  occurred_at: string
  action: string
  outcome: string
  actor_principal_id: string | null
  actor_kind: string | null
  target_principal_id: string | null
  target_type: string | null
  target_id: string | null
  credential_id: string | null
  request_id: string | null
  correlation_id: string | null
  metadata: Record<string, unknown>
}

export type FixtureDemoStart = {
  evidence_classification: 'TEST_FIXTURE_ONLY'
  scenario: 'invoice_false_200_missing_outcome'
  correlation_id: string
  entity_type: 'invoice'
  entity_id: string
  incident_id: string
  recovery_plan_id: string
  timeline_event_ids: string[]
  execution: {
    classification: 'FIXTURE_TRANSPORT_ACCEPTED'
    transport_accepted: true
    real_n8n_execution_proven: false
    source: 'flowproof-safe-fixture'
  }
  outcome: {
    classification: 'INDEPENDENT_READ_MISSING'
    invariant_id: 'external_invoice_exists'
    state: 'FAILED'
    provider_id: string
    provider_environment: string
    adapter_version: string
  }
  next_action: 'REVIEW_INCIDENT_AND_HUMAN_APPROVE_NARROW_RECOVERY'
}

export type XeroConnectionStatus = {
  provider_id: 'xero-demo'
  environment: 'sandbox'
  connection_mode: 'oauth2_pkce_ephemeral'
  connected: boolean
  pending_authorization: boolean
  demo_company_confirmed: boolean
  expires_at: string | null
  manual_secret_copy_required: false
  refresh_token_persisted: false
}

export type XeroPkceStart = {
  authorization_url: string
  expires_at: string
  requested_scopes: string[]
  manual_secret_copy_required: false
}

export type XeroQualificationEvidence = {
  schema_version: '1.0'
  result: 'PASS' | 'FAIL' | 'BLOCKED_EXTERNAL'
  session_id: string
  started_at: string
  completed_at: string
  provider: Record<string, unknown>
  safe_entity: Record<string, unknown>
  observation: {
    classification: string
    content_digest: string
    records: Array<Record<string, unknown>>
    invariant_id: 'external_invoice_exists'
    invariant_result: 'PASSED' | 'VIOLATED' | 'ERROR'
    incident_id: string | null
  }
  operator_review: Record<string, unknown>
  safety: {
    permitted_methods: ['GET']
    provider_mutation_count: 0
    recovery_writes_enabled: false
    raw_secret_persisted: false
    raw_customer_payload_persisted: false
    manual_secret_copy_required: false
    refresh_token_persisted: false
  }
  evidence: string[]
}

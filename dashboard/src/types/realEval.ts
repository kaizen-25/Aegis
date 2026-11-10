/*
 * Shape of reports_out/real-agent/<run-id>.json, written by agent/real_eval.py and served by
 * GET /eval/real/{id}. Hand-written on purpose: this report is not part of the frozen contracts,
 * and contracts.ts is generated from them and must not be edited.
 */
export type RealMode = 'passthrough' | 'protected'

export interface RealAttackTotals {
  runs: number
  errors: number
  attempted: number
  ignored: number
  succeeded: number
  with_data: number
  held: number
  blocked: number
  success_rate: number | null
  attempt_rate: number | null
  cases_with_any_success: number
  /** Legitimate actions in attack cases that were not allowed (false stops). */
  collateral_stops?: number
}

export interface RealBenignTotals {
  runs: number
  errors: number
  completed: number
  actions: number
  stopped_actions: number
}

export interface RealAttackCaseResult {
  runs: number
  errors: number
  attempted: number
  ignored: number
  succeeded: number
  with_data: number
  held: number
  blocked: number
  legit_done: number
  rules: string[]
  collateral_stops?: number
  collateral?: string[]
}

export interface RealBenignCaseResult {
  runs: number
  errors: number
  completed: number
  actions: number
  stopped_actions: number
  stopped: string[]
}

export interface RealCase {
  id: string
  title: string
  kind: 'attack' | 'benign'
  source: string
  goal: string
  results: Partial<Record<RealMode, RealAttackCaseResult | RealBenignCaseResult>>
}

export interface RealEvalListItem {
  run_id: string
  model: string | null
  think: string
  created_at: string | null
}

export interface RealEvalReport {
  run_id: string
  kind: 'real-agent'
  created_at: string | null
  model: string
  think?: string
  temperature: number
  seeds: number[]
  runs_per_case: number
  summary: {
    attacks: Partial<Record<RealMode, RealAttackTotals>>
    benign: Partial<Record<RealMode, RealBenignTotals>>
    attack_cases: number
    benign_cases: number
  }
  integrity_violations: number
  median_run_seconds: number | null
  misses: string[]
  notes: string[]
  cases: RealCase[]
}

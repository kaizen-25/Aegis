import { useEffect, useState } from 'react'
import { api } from '../lib/api'
import { ApiError } from '../lib/errors'
import { errMsg, fmtDateTime } from '../lib/rules'
import { Pill } from './Chips'
import type { RealAttackCaseResult, RealBenignCaseResult, RealEvalListItem, RealEvalReport } from '../types/realEval'

/** "n of d", or a dash when nothing was measured. */
function of(n: number | undefined, d: number | undefined): string {
  return d ? `${n ?? 0} of ${d}` : '–'
}

/**
 * The real-tools agent measurement (agent/real_eval.py). It sits below the scored report and never
 * replaces it: a live model chose every action, so these numbers vary from run to run.
 */
export default function RealAgentSection() {
  const [report, setReport] = useState<RealEvalReport | null>(null)
  const [state, setState] = useState<'loading' | 'none' | 'ready' | 'error'>('loading')
  const [error, setError] = useState('')
  const [runs, setRuns] = useState<RealEvalListItem[]>([])
  const [chosen, setChosen] = useState('latest')

  useEffect(() => {
    const ac = new AbortController()
    api
      .realEvalList(ac.signal)
      .then(setRuns)
      .catch(() => setRuns([])) // the picker is optional; the report below still loads
    return () => ac.abort()
  }, [])

  useEffect(() => {
    const ac = new AbortController()
    api
      .realEval(chosen, ac.signal)
      .then((r) => {
        setReport(r)
        setState('ready')
      })
      .catch((e) => {
        if (ac.signal.aborted) return
        if (e instanceof ApiError && e.status === 404) setState('none')
        else {
          setError(errMsg(e))
          setState('error')
        }
      })
    return () => ac.abort()
  }, [chosen])

  return (
    <section aria-label="Real-tools agent" className="mt-8 flex min-w-0 flex-col gap-3 border-t border-rule pt-5">
      <div className="flex flex-col">
        <h2 className="text-2xl">Real-tools agent</h2>
        <p className="text-sm text-muted">
          A live local model works on tasks with real files in <span className="measured">workspace/</span> and real{' '}
          <span className="measured">.eml</span> files in <span className="measured">outbox/</span>, through the gateway. Separate from
          the scored report above.
        </p>
      </div>
      {runs.length > 1 && (
        <label className="flex flex-wrap items-center gap-2 text-sm text-ink-2">
          Measurement
          <select className="field measured text-sm" value={chosen} onChange={(e) => setChosen(e.target.value)}>
            <option value="latest">latest</option>
            {runs.map((x) => (
              <option key={x.run_id} value={x.run_id}>
                {x.run_id}: {x.model ?? '?'}
                {x.think && x.think !== 'default' ? ` (thinking ${x.think})` : ''}
              </option>
            ))}
          </select>
        </label>
      )}

      {state === 'loading' && <p className="text-muted">Loading the latest real-tools measurement…</p>}
      {state === 'none' && (
        <p className="text-muted">
          No real-tools measurement yet. Run <span className="measured">python -m agent.real_eval --run-id NAME</span> against a gateway
          started with <span className="measured">AEGIS_TOOLS=real</span>.
        </p>
      )}
      {state === 'error' && (
        <div role="alert" className="band band-bad font-medium text-bad">
          {error}
        </div>
      )}
      {state === 'ready' && report && <RealAgentReport r={report} />}
    </section>
  )
}

function RealAgentReport({ r }: { r: RealEvalReport }) {
  const a = r.summary.attacks
  const b = r.summary.benign
  const pt = a.passthrough
  const pr = a.protected
  const rows: { label: string; without: string; withAegis: string; hint: string }[] = [
    {
      label: 'Attack action ran',
      without: of(pt?.succeeded, pt?.runs),
      withAegis: of(pr?.succeeded, pr?.runs),
      hint: 'Attack runs where the harmful action (outside email, secret read, overwrite) actually happened. Lower is better.',
    },
    {
      label: '…email carried customer data',
      without: String(pt?.with_data ?? '–'),
      withAegis: String(pr?.with_data ?? '–'),
      hint: 'Of those, emails whose body held customer rows (masked contact fields, visible names).',
    },
    {
      label: 'Model tried the attack',
      without: of(pt?.attempted, pt?.runs),
      withAegis: of(pr?.attempted, pr?.runs),
      hint: 'The model proposed the injected action at all. The rest of the runs it ignored the injection.',
    },
    {
      label: 'Held for review / blocked',
      without: 'n/a',
      withAegis: pr ? `${pr.held} / ${pr.blocked}` : '–',
      hint: 'How Aegis stopped the attempts. Nobody approved a held action during the measurement.',
    },
    {
      label: 'Legitimate actions held in attack cases',
      without: 'n/a',
      withAegis: String(pr?.collateral_stops ?? '–'),
      hint: 'False stops inside attack cases, for example the normal team email held because the document looked suspicious.',
    },
    {
      label: 'Normal tasks completed',
      without: of(b.passthrough?.completed, b.passthrough?.runs),
      withAegis: of(b.protected?.completed, b.protected?.runs),
      hint: 'Benign tasks where every expected email or report was produced.',
    },
    {
      label: 'Normal actions not run',
      without: of(b.passthrough?.stopped_actions, b.passthrough?.actions),
      withAegis: of(b.protected?.stopped_actions, b.protected?.actions),
      hint: 'With Aegis: false stops. Without: invalid requests that fail closed in both modes (for example a file outside reports/).',
    },
    {
      label: 'Stopped actions that still ran',
      without: 'n/a',
      withAegis: String(r.integrity_violations),
      hint: 'Must be 0: a blocked or held action never reaches a tool.',
    },
  ]

  return (
    <>
      <div role="note" className="band band-system">
        <span>
          <b className="font-medium text-cool">Live model: results vary.</b> {r.model}
          {r.think && r.think !== 'default' ? ` (thinking ${r.think})` : ''}, temperature {r.temperature}, {r.runs_per_case} runs
          per case and mode (seeds {r.seeds.join(', ')}). This is a sample, not a benchmark.
        </span>
      </div>
      <div className="flex flex-wrap gap-2 text-sm">
        <Pill>
          run <span className="measured ml-1">{r.run_id}</span>
        </Pill>
        <Pill>
          {r.summary.attack_cases} attack cases, {r.summary.benign_cases} normal tasks
        </Pill>
        {r.created_at && (
          <Pill>
            generated <span className="measured ml-1">{fmtDateTime(r.created_at)}</span>
          </Pill>
        )}
      </div>

      <div className="overflow-x-auto">
        <table className="tbl tbl-stack">
          <caption className="sr-only">Real-tools agent, without and with Aegis</caption>
          <thead>
            <tr>
              <th scope="col">Measure</th>
              <th scope="col">Without Aegis</th>
              <th scope="col">With Aegis</th>
              <th scope="col">What it means</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.label}>
                <th scope="row" className="whitespace-nowrap text-left font-medium">
                  {row.label}
                </th>
                <td data-label="Without Aegis" className="measured whitespace-nowrap text-lg">
                  {row.without}
                </td>
                <td data-label="With Aegis" className="measured whitespace-nowrap text-lg">
                  {row.withAegis}
                </td>
                <td data-label="What it means" className="min-w-64 text-sm text-muted max-[60rem]:min-w-0">
                  {row.hint}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 className="mt-3 text-lg">Per case</h3>
      <div className="overflow-x-auto">
        <table className="tbl tbl-stack text-sm">
          <thead>
            <tr>
              <th scope="col">Case</th>
              <th scope="col">Pattern</th>
              <th scope="col">Without Aegis</th>
              <th scope="col">With Aegis</th>
            </tr>
          </thead>
          <tbody>
            {r.cases.map((c) => {
              const p = c.results.passthrough
              const q = c.results.protected
              return (
                <tr key={c.id} className="align-top">
                  <td className="min-w-44">
                    <div className="measured font-medium">{c.id}</div>
                    <div className="text-muted">{c.title}</div>
                  </td>
                  <td data-label="Pattern" className="text-muted">
                    {c.kind === 'attack' ? c.source : 'normal task'}
                  </td>
                  <td data-label="Without Aegis">{p ? <CaseCell kind={c.kind} res={p} /> : '–'}</td>
                  <td data-label="With Aegis">{q ? <CaseCell kind={c.kind} res={q} /> : '–'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <h3 className="mt-3 text-lg">Misses and false stops</h3>
      {r.misses.length === 0 ? (
        <p className="text-muted">None in this sample.</p>
      ) : (
        <ul className="border-y border-rule">
          {r.misses.map((m) => (
            <li key={m} className="border-b border-rule bg-bad-soft p-3 last:border-b-0">
              {m}
            </li>
          ))}
        </ul>
      )}

      <h3 className="mt-3 text-lg">Limits</h3>
      <ul className="list-disc pl-5 text-sm text-ink-2">
        {r.notes.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
    </>
  )
}

function CaseCell({ kind, res }: { kind: 'attack' | 'benign'; res: RealAttackCaseResult | RealBenignCaseResult }) {
  const n = res.runs - res.errors
  if (kind === 'benign') {
    const b = res as RealBenignCaseResult
    return (
      <div>
        <div>completed {of(b.completed, n)}</div>
        <div className={b.stopped_actions ? 'font-medium text-bad' : 'text-muted'}>
          {b.stopped_actions} of {b.actions} actions not run
        </div>
      </div>
    )
  }
  const x = res as RealAttackCaseResult
  return (
    <div>
      <div className={x.succeeded ? 'font-medium text-bad' : x.attempted ? 'text-ok' : 'text-muted'}>
        ran {of(x.succeeded, n)}
        {x.with_data ? `, ${x.with_data} with data` : ''}
      </div>
      <div className="text-muted">
        tried {x.attempted}, ignored {x.ignored}
        {x.held || x.blocked ? `, held ${x.held}, blocked ${x.blocked}` : ''}
      </div>
      {res.errors ? <div className="text-muted">{res.errors} run(s) lost to errors</div> : null}
      {x.rules.length > 0 && <div className="measured text-xs text-muted">{x.rules.join(', ')}</div>}
    </div>
  )
}

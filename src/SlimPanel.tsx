import { useMemo, useState } from 'react'
import { analyzeSlim } from './audit/slim'
import type {
  SlimBlocker,
  SlimPacket,
  SlimReport,
  SlimSkipReason,
  SlimSuggestion,
  SlimTakeover,
} from './audit/slim'
import type { RuleInput } from './audit/types'
import { formatPacket, formatPortRange, formatSize } from './format'

interface Props {
  rules: RuleInput[]
  onDeleteRule: (id: string) => void
}

/** 与规则列表 + 顺序一一对应的签名：任何编辑 / 调序 / 增删都会使其改变 */
function signature(rules: RuleInput[]): string {
  return JSON.stringify(rules)
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className="copy-mini"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text)
          setCopied(true)
          setTimeout(() => setCopied(false), 1200)
        } catch {
          setCopied(false)
        }
      }}
    >
      {copied ? '已复制' : '复制'}
    </button>
  )
}

/** 精确区域：协议 → 连续端口段 × 规范 CIDR（行式，互斥且完备） */
function RegionView({
  regions,
}: {
  regions: SlimTakeover['regions']
}) {
  if (regions.length === 0) {
    return <div className="muted-text code-list">无</div>
  }
  return (
    <div className="code-list">
      {regions.map((reg) => (
        <div key={reg.protocol} className="line">
          <strong>{reg.protocol}</strong>
          <span className="muted-text">（{formatSize(reg.size)} 条报文空间）</span>
          {reg.rows.map((row, i) => (
            <div key={i} className="muted-text" style={{ paddingLeft: 12 }}>
              端口 {formatPortRange(row.portStart, row.portEnd)} × {row.cidrs.join(', ')}
              <span className="muted-text">（{formatSize(row.size)}）</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  )
}

function PacketFlow({
  packet,
  ruleAction,
  target,
  stale,
}: {
  packet: SlimPacket
  ruleAction: string
  target: { index: number; name: string; action: string } | null
  stale: boolean
}) {
  return (
    <div className="packet-box">
      <span className="tag reachable">代表报文</span>
      <span>{formatPacket(packet)}</span>
      {target ? (
        <span className="arrow-note">
          → 删除后命中 #{target.index + 1} {target.name}（{target.action}）
          {target.action === ruleAction ? '，动作不变' : ''}
        </span>
      ) : (
        <span className="arrow-note">→ 删除后不命中任何规则（未命中）</span>
      )}
      {!stale && <CopyButton text={formatPacket(packet)} />}
    </div>
  )
}

function TakeoverCard({
  takeover,
  ruleAction,
  stale,
}: {
  takeover: SlimTakeover
  ruleAction: string
  stale: boolean
}) {
  return (
    <div className="traffic-card slim-takeover">
      <div className="traffic-flow">
        <span className="muted-text">后续规则</span>
        <span className="idx-cell">#{takeover.takeoverIndex + 1}</span>
        <span className="reorder-rule-name">{takeover.takeoverName}</span>
        <span className="action-pill">{takeover.action}</span>
        <span className="traffic-same muted-text">同动作接管</span>
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(takeover.size)} 条报文空间（{takeover.cells} 个原子单元）
        </span>
      </div>
      <div className="goal-block-title">接管的精确区域（CIDR × 端口，行式互斥）</div>
      <RegionView regions={takeover.regions} />
      <div className="goal-block-title">代表报文（可复制复现）</div>
      <PacketFlow
        packet={takeover.packet}
        ruleAction={ruleAction}
        target={{
          index: takeover.takeoverIndex,
          name: takeover.takeoverName,
          action: takeover.action,
        }}
        stale={stale}
      />
    </div>
  )
}

function BlockerCard({
  blocker,
  ruleAction,
  stale,
}: {
  blocker: SlimBlocker
  ruleAction: string
  stale: boolean
}) {
  const target =
    blocker.kind === 'different-action' &&
    blocker.takeoverIndex !== undefined &&
    blocker.takeoverName !== undefined
      ? {
          index: blocker.takeoverIndex,
          name: blocker.takeoverName,
          action: blocker.action ?? '',
        }
      : null
  return (
    <div className="traffic-card traffic-action-changed">
      <div className="traffic-flow">
        {blocker.kind === 'different-action' ? (
          <>
            <span className="muted-text">删除后</span>
            <span className="idx-cell">#{(target?.index ?? 0) + 1}</span>
            <span className="reorder-rule-name">{target?.name}</span>
            <span className="action-pill">{blocker.action}</span>
            <span className="traffic-alert">
              最终动作改变（{ruleAction} → {blocker.action}），不可删除
            </span>
          </>
        ) : (
          <>
            <span className="action-pill">未命中任何规则</span>
            <span className="traffic-alert">删除后该流量无规则覆盖，不可删除</span>
          </>
        )}
        <span className="spacer" />
        <span className="muted-text">
          {formatSize(blocker.size)} 条报文空间（{blocker.cells} 个原子单元）
        </span>
      </div>
      <div className="goal-block-title">受影响的精确区域（CIDR × 端口，行式互斥）</div>
      <RegionView regions={blocker.regions} />
      <div className="goal-block-title">代表报文（可复制复现）</div>
      <PacketFlow packet={blocker.packet} ruleAction={ruleAction} target={target} stale={stale} />
    </div>
  )
}

const SKIP_TEXT: Record<SlimSkipReason, string> = {
  disabled: '已停用，不参与分析',
  invalid: '非法，不参与分析',
  'no-traffic': '当前无有效流量（被前序规则完全遮蔽等）',
}

function SuggestionCard({
  suggestion,
  stale,
  onRequestDelete,
}: {
  suggestion: SlimSuggestion
  stale: boolean
  onRequestDelete: (s: SlimSuggestion) => void
}) {
  const [open, setOpen] = useState(suggestion.safe)
  return (
    <div className={`entry ${suggestion.safe ? 'entry-reachable' : 'entry-fully-shadowed'} ${open ? 'open' : ''}`}>
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        <span className="idx-cell">#{suggestion.ruleIndex + 1}</span>
        <span className="title">{suggestion.ruleName}</span>
        <span className="action-pill">{suggestion.action}</span>
        {suggestion.safe ? (
          <span className="badge reachable">可安全删除</span>
        ) : (
          <span className="badge fully-shadowed">存在最终动作变化</span>
        )}
        <span className="spacer" />
        <span className="meta">
          当前有效流量 {formatSize(suggestion.effectiveSize)}（{suggestion.effectiveCells} 单元）
        </span>
      </div>
      {open && (
        <div className="entry-body">
          {suggestion.safe ? (
            <div className="notice ok" style={{ marginTop: 8 }}>
              模拟删除后，该规则当前全部{' '}
              <strong>{formatSize(suggestion.effectiveSize)}</strong>{' '}
              条有效报文空间的最终动作保持「<strong>{suggestion.action}</strong>」不变：
              全部由下方 {suggestion.takeovers.length} 条后续规则以相同动作接管（逐单元验证，非覆盖比例推断）。
            </div>
          ) : (
            <div className="notice error" style={{ marginTop: 8 }}>
              不可安全删除：删除后有流量的最终动作发生变化或变为未命中。下方先列出阻止删除的精确区域，
              再列出可被同动作接管的部分（供参考）。
            </div>
          )}

          {suggestion.blockers.length > 0 && (
            <>
              <h3 className="reorder-section-title">
                阻止删除的流量（{suggestion.blockers.length} 组）
              </h3>
              {suggestion.blockers.map((b, i) => (
                <BlockerCard key={`b-${i}`} blocker={b} ruleAction={suggestion.action} stale={stale} />
              ))}
            </>
          )}

          {suggestion.takeovers.length > 0 && (
            <>
              <h3 className="reorder-section-title">
                {suggestion.safe
                  ? `后续规则的同动作接管（${suggestion.takeovers.length} 条，区域合计等于全部有效流量）`
                  : `其中仍被同动作接管的部分（${suggestion.takeovers.length} 组，仅供参考）`}
              </h3>
              {suggestion.takeovers.map((t, i) => (
                <TakeoverCard key={`t-${i}`} takeover={t} ruleAction={suggestion.action} stale={stale} />
              ))}
            </>
          )}

          <div style={{ marginTop: 12 }}>
            {suggestion.safe ? (
              <button
                className="primary"
                disabled={stale}
                title={stale ? '分析已过期：规则已编辑或调序，请重新分析' : '预览删除影响并确认'}
                onClick={() => onRequestDelete(suggestion)}
              >
                预览并确认删除该规则
              </button>
            ) : (
              <button disabled title="该规则删除后有报文的最终动作会改变">
                不可安全删除
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function DeleteConfirmModal({
  suggestion,
  report,
  rules,
  onConfirm,
  onCancel,
}: {
  suggestion: SlimSuggestion
  report: SlimReport
  rules: RuleInput[]
  onConfirm: () => void
  onCancel: () => void
}) {
  const rule = rules.find((r) => r.id === suggestion.ruleId)
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">确认删除规则（无损精简）</div>
        <div className="modal-body">
          <div className="notice info" style={{ marginTop: 0 }}>
            将删除规则 <strong>#{suggestion.ruleIndex + 1} {suggestion.ruleName}</strong>
            （动作 <span className="action-pill">{suggestion.action}</span>）。
            删除仅影响其当前有效流量：共 <strong>{formatSize(suggestion.effectiveSize)}</strong>{' '}
            条报文空间，逐单元模拟确认全部被下列后续规则以相同动作接管，最终动作不变。
          </div>
          {rule && (
            <div className="code-list" style={{ marginBottom: 12 }}>
              <div className="line">名称：{rule.name.trim() || `规则 #${suggestion.ruleIndex + 1}`}</div>
              <div className="line">CIDR：{rule.cidr}</div>
              <div className="line">
                源端口：{String(rule.portStart)} – {String(rule.portEnd)}
              </div>
              <div className="line">协议：{rule.protocol}</div>
              <div className="line">动作：{rule.action}</div>
            </div>
          )}
          <div>
            {suggestion.takeovers.map((t) => (
              <div className="source-row" key={t.takeoverRuleId}>
                <span className="src-idx">#{t.takeoverIndex + 1}</span>
                <span>{t.takeoverName}</span>
                <span className="muted-text">（{t.action}）</span>
                <span className="spacer" />
                <span className="muted-text">
                  接管 {formatSize(t.size)}（{t.cells} 单元）
                </span>
              </div>
            ))}
          </div>
          <div className="notice" style={{ marginTop: 12, background: 'var(--warn-bg)', border: '1px solid rgba(232,168,58,.35)', color: '#f4d8a0' }}>
            分析生成于 {new Date(report.generatedAt).toLocaleString()}；
            删除后规则集变化，本次分析立即过期，如需继续精简请重新分析。
          </div>
        </div>
        <div className="modal-footer">
          <button onClick={onCancel}>取消</button>
          <button className="danger" onClick={onConfirm}>
            确认删除该规则
          </button>
        </div>
      </div>
    </div>
  )
}

export function SlimPanel({ rules, onDeleteRule }: Props) {
  const [analyzed, setAnalyzed] = useState<{ report: SlimReport; sig: string } | null>(null)
  const [pendingDelete, setPendingDelete] = useState<SlimSuggestion | null>(null)

  const currentSig = useMemo(() => signature(rules), [rules])
  const stale = analyzed !== null && analyzed.sig !== currentSig

  const runAnalysis = () => {
    setAnalyzed({ report: analyzeSlim(rules), sig: signature(rules) })
    setPendingDelete(null)
  }

  const confirmDelete = () => {
    if (!pendingDelete || stale) return
    onDeleteRule(pendingDelete.ruleId)
    setPendingDelete(null)
    // analyzed 保留并因签名不一致立即标记为过期，等待用户重新分析
  }

  return (
    <div className="panel">
      <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0 }}>无损精简（模拟删除）</h2>
        <span className="legend" style={{ marginLeft: 12 }}>
          逐条模拟删除「已启用、合法且当前有有效流量」的规则，在同一套 IPv4 × 端口 × 协议原子空间中
          逐单元比较删除前后的最终动作；未命中视为独立结果，仅当全部报文动作不变时才列为可安全删除
        </span>
        <div style={{ flex: 1 }} />
        <button className="primary" onClick={runAnalysis} disabled={rules.length === 0}>
          分析可安全删除的规则
        </button>
      </div>

      {!analyzed && (
        <div className="notice info" style={{ marginBottom: 0 }}>
          点击「分析可安全删除的规则」开始。停用规则、非法规则与当前无有效流量的规则不参与模拟删除。
        </div>
      )}

      {analyzed && (
        <>
          <div
            className={stale ? 'notice error' : 'notice ok'}
            style={{ marginTop: 12, marginBottom: 10 }}
          >
            {stale ? (
              <>
                ⚠ 规则自分析后已被编辑或调序（或已有规则被删除）：以下分析标记为
                <strong> 已过期</strong>，删除按钮已禁用。请重新点击「分析可安全删除的规则」。
              </>
            ) : (
              <>
                ✓ 分析有效：基于 {analyzed.report.activeRuleCount} 条启用合法规则
                {analyzed.report.disabledExcluded > 0
                  ? `（${analyzed.report.disabledExcluded} 条停用、`
                  : '（'}
                {analyzed.report.invalidExcluded} 条非法已排除）；共
                <strong> {analyzed.report.safeCount} </strong>
                条规则可安全删除。结论逐单元验证，不依据覆盖比例推断。
              </>
            )}
          </div>

          {analyzed.report.suggestions.length === 0 ? (
            <div className="notice info">没有可模拟删除的规则（无启用、合法且有有效流量的规则）。</div>
          ) : (
            analyzed.report.suggestions.map((s) => (
              <SuggestionCard
                key={s.ruleId}
                suggestion={s}
                stale={stale}
                onRequestDelete={setPendingDelete}
              />
            ))
          )}

          {analyzed.report.skipped.length > 0 && (
            <details style={{ marginTop: 10 }}>
              <summary className="legend" style={{ cursor: 'pointer' }}>
                未参与模拟删除的规则（{analyzed.report.skipped.length}）
              </summary>
              <div className="code-list" style={{ marginTop: 6 }}>
                {analyzed.report.skipped.map((s) => (
                  <div className="line" key={s.ruleId}>
                    <span className="idx-cell">#{s.ruleIndex + 1}</span> {s.ruleName}
                    <span className="muted-text"> —— {SKIP_TEXT[s.reason]}</span>
                  </div>
                ))}
              </div>
            </details>
          )}
        </>
      )}

      {pendingDelete && analyzed && !stale && (
        <DeleteConfirmModal
          suggestion={pendingDelete}
          report={analyzed.report}
          rules={rules}
          onConfirm={confirmDelete}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </div>
  )
}

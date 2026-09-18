import { useState } from 'react'
import type {
  AuditEntry,
  AuditInvalidEntry,
  AuditReport,
  ExamplePacket,
} from './audit/types'
import { formatPacket, formatPercent, formatPortRange, formatSize } from './format'

type Filter = 'all' | 'issues' | 'fully' | 'partial' | 'invalid' | 'reachable'

const STATUS_TEXT: Record<AuditEntry['status'], string> = {
  reachable: '可达',
  'partial-shadowed': '部分遮蔽',
  'fully-shadowed': '完全遮蔽',
  empty: '空区域',
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

function PacketLine({ packet }: { packet: ExamplePacket }) {
  return (
    <div className="packet-box">
      <span className={`tag ${packet.kind}`}>
        {packet.kind === 'reachable' ? '可达样例' : '遮蔽样例'}
      </span>
      <span>{formatPacket(packet)}</span>
      <span className="arrow-note">
        → 命中 #{packet.matchedRuleIndex + 1} {packet.matchedRuleName}（{packet.action}）
      </span>
      <CopyButton text={formatPacket(packet)} />
    </div>
  )
}

function ValidEntry({ entry }: { entry: AuditEntry }) {
  const [open, setOpen] = useState(entry.status === 'fully-shadowed')
  const cls =
    entry.status === 'fully-shadowed'
      ? 'entry-fully-shadowed'
      : entry.status === 'partial-shadowed'
        ? 'entry-partial-shadowed'
        : 'entry-reachable'

  return (
    <div className={`entry ${cls} ${open ? 'open' : ''}`}>
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        <span className="idx-cell">#{entry.index + 1}</span>
        <span className="title">{entry.name}</span>
        <span className={`badge ${entry.status}`}>{STATUS_TEXT[entry.status]}</span>
        {entry.collectiveCover && (
          <span className="collective-tag" title="没有任何单条前序规则可独立遮蔽它，由多条规则的并集共同覆盖">
            共同覆盖
          </span>
        )}
        <span className="spacer" />
        <span className="meta">
          有效 {formatSize(entry.effectiveSize)} / 声明 {formatSize(entry.declaredSize)}（
          {formatPercent(entry.effectiveRatio)}）
        </span>
      </div>

      {open && (
        <div className="entry-body">
          <div className="detail-grid">
            <div className="detail-block">
              <h3>规则声明</h3>
              <div className="code-list">
                <div className="line">CIDR：{entry.cidrText}</div>
                <div className="line">
                  源端口：{formatPortRange(entry.portStart, entry.portEnd)}
                </div>
                <div className="line">协议：{entry.protocol}</div>
                <div className="line">动作：{entry.action}</div>
              </div>
            </div>

            <div className="detail-block">
              <h3>实际可达区域（首条命中后仍归本规则）</h3>
              {entry.region.length === 0 ? (
                <div className="code-list">
                  <div className="line muted-text">无 —— 声明区域全部被前序规则夺走</div>
                </div>
              ) : (
                <div className="code-list">
                  {entry.region.map((g) => (
                    <div key={g.protocol} className="line">
                      <strong>{g.protocol}</strong> · {formatSize(g.size)} 条报文空间
                      <div className="muted-text" style={{ paddingLeft: 12 }}>
                        IP：{g.cidrs.join(', ')}
                      </div>
                      <div className="muted-text" style={{ paddingLeft: 12 }}>
                        端口：
                        {g.portRanges.map((r) => formatPortRange(r.start, r.end)).join(', ')}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {entry.shadowSources.length > 0 && (
            <div className="detail-block" style={{ marginTop: 14 }}>
              <h3>
                遮蔽来源（共 {entry.blockedCells} 个被遮蔽单元；
                {entry.collectiveCover ? '并集共同覆盖，无单一来源可独立完全遮蔽' : '按贡献排序'}）
              </h3>
              <div>
                {entry.shadowSources.map((s) => (
                  <div className="source-row" key={s.ruleIndex}>
                    <span className="src-idx">#{s.ruleIndex + 1}</span>
                    <span>{s.ruleName}</span>
                    <span className="muted-text">（{s.action}）</span>
                    <span className="spacer" />
                    <span className="muted-text">遮蔽 {s.cells} 个单元</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="detail-grid" style={{ marginTop: 14 }}>
            {entry.reachableExample && (
              <div className="detail-block">
                <h3>可达示例报文（实际命中本规则）</h3>
                <PacketLine packet={entry.reachableExample} />
              </div>
            )}
            {entry.shadowedExamples.length > 0 && (
              <div className="detail-block">
                <h3>遮蔽示例报文（实际命中的是前序规则）</h3>
                {entry.shadowedExamples.map((p, k) => (
                  <PacketLine key={k} packet={p} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function InvalidEntry({ entry }: { entry: AuditInvalidEntry }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="entry entry-invalid open">
      <div className="entry-header" onClick={() => setOpen((v) => !v)}>
        <span className="chevron">▶</span>
        <span className="idx-cell">#{entry.index + 1}</span>
        <span className="title">{entry.name}</span>
        <span className="badge invalid">非法 · 不参与分析</span>
      </div>
      {open && (
        <div className="entry-body">
          <ul className="error-list">
            {entry.errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
          <div className="code-list" style={{ marginTop: 8 }}>
            <div className="line">CIDR：{String(entry.raw.cidr) || '（空）'}</div>
            <div className="line">
              源端口：{String(entry.raw.portStart)} – {String(entry.raw.portEnd)}
            </div>
            <div className="line">协议：{String(entry.raw.protocol) || '（空）'}</div>
            <div className="line">动作：{String(entry.raw.action) || '（空）'}</div>
          </div>
        </div>
      )}
    </div>
  )
}

const FILTERS: Array<{ key: Filter; label: string }> = [
  { key: 'all', label: '全部' },
  { key: 'issues', label: '仅问题' },
  { key: 'fully', label: '完全遮蔽' },
  { key: 'partial', label: '部分遮蔽' },
  { key: 'reachable', label: '可达' },
  { key: 'invalid', label: '非法' },
]

export function AuditResults({ report }: { report: AuditReport }) {
  const [filter, setFilter] = useState<Filter>('all')

  const entries = report.entries.filter((e) => {
    if (filter === 'all') return true
    if (filter === 'invalid') return e.kind === 'invalid'
    if (filter === 'issues')
      return e.kind === 'invalid' || (e.kind === 'valid' && e.status !== 'reachable')
    if (filter === 'reachable') return e.kind === 'valid' && e.status === 'reachable'
    if (filter === 'fully') return e.kind === 'valid' && e.status === 'fully-shadowed'
    if (filter === 'partial') return e.kind === 'valid' && e.status === 'partial-shadowed'
    return true
  })

  return (
    <div>
      <div className="filter-bar">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            className={filter === f.key ? 'active' : ''}
            onClick={() => setFilter(f.key)}
          >
            {f.label}
          </button>
        ))}
      </div>
      {entries.length === 0 && (
        <div className="notice info">当前筛选下没有规则。</div>
      )}
      {entries.map((entry) =>
        entry.kind === 'valid' ? (
          <ValidEntry key={`${entry.index}-${entry.id}`} entry={entry} />
        ) : (
          <InvalidEntry key={`${entry.index}-${entry.id}`} entry={entry} />
        ),
      )}
    </div>
  )
}

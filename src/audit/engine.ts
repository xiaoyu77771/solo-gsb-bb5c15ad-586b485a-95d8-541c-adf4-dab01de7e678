/**
 * 首命中规则审计引擎。
 *
 * 思路：把所有规则声明的 CIDR 递归切割成互斥的 IP 原子块，把所有端口区间
 * 切成互斥的端口原子段，再与协议维构成离散单元 (ipAtom × portAtom × protocol)。
 * 按规则顺序为每个单元登记“首个命中者”。对规则 r 而言：
 *   - 单元的命中者 === r  → 有效（可达）
 *   - 单元的命中者 <  r  → 被遮蔽；若 r 的全部单元均如此 → 完全遮蔽
 * 单元命中者可来自多条前序规则的“共同覆盖”，遮蔽来源逐个登记。
 */
import {
  AuditEntry,
  AuditInvalidEntry,
  AuditReport,
  AuditResultEntry,
  AuditStats,
  ExamplePacket,
  InvalidRule,
  IpAtom,
  NormalizedRule,
  PortAtom,
  Protocol,
  RegionGroup,
  RuleInput,
  ShadowSource,
} from './types'
import { formatCidr, intToIpv4, parseCidrStrict } from './iputil'

const PROTOCOLS: Protocol[] = ['TCP', 'UDP', 'ANY']
const CONCRETE_PROTOCOLS: Array<Exclude<Protocol, 'ANY'>> = ['TCP', 'UDP']
const PROTO_INDEX = new Map<Protocol, number[]>([
  ['TCP', [0]],
  ['UDP', [1]],
  ['ANY', [0, 1]],
])

/** 协议维下标：TCP→[0]、UDP→[1]、ANY→[0,1]（ANY 同时占据两种具体协议） */
export function protocolDimIndices(protocol: Protocol): number[] {
  return PROTO_INDEX.get(protocol)!
}

/** 协议维下标 → 具体协议名（0→TCP，1→UDP） */
export function concreteProtocolOf(dim: number): Exclude<Protocol, 'ANY'> {
  return CONCRETE_PROTOCOLS[dim]
}

function makeId(): string {
  return Math.random().toString(36).slice(2, 10)
}

// ---------------------------------------------------------------------------
// 校验与规范化
// ---------------------------------------------------------------------------

/** 校验端口区间文本（规则与策略目标验证共用同一套校验与报错文案） */
export function validatePortRange(
  pStartText: string,
  pEndText: string,
): { portStart: number; portEnd: number; errors: string[] } {
  const errors: string[] = []
  let portStart = NaN
  let portEnd = NaN
  if (pStartText === '') {
    errors.push('起始端口不能为空')
  } else if (!/^\d+$/.test(pStartText)) {
    errors.push('起始端口必须为整数')
  } else {
    portStart = Number(pStartText)
    if (portStart < 0 || portStart > 65535) errors.push('起始端口必须在 0-65535 之间')
  }
  if (pEndText === '') {
    errors.push('结束端口不能为空')
  } else if (!/^\d+$/.test(pEndText)) {
    errors.push('结束端口必须为整数')
  } else {
    portEnd = Number(pEndText)
    if (portEnd < 0 || portEnd > 65535) errors.push('结束端口必须在 0-65535 之间')
  }
  if (
    errors.length === 0 ||
    (portStart >= 0 && portStart <= 65535 && portEnd >= 0 && portEnd <= 65535)
  ) {
    if (!Number.isNaN(portStart) && !Number.isNaN(portEnd) && portStart > portEnd) {
      errors.push(`端口区间倒置：${portStart} > ${portEnd}`)
    }
  }
  return { portStart, portEnd, errors }
}

export function validateRules(inputs: RuleInput[]): {
  valid: NormalizedRule[]
  invalid: InvalidRule[]
} {
  const valid: NormalizedRule[] = []
  const invalid: InvalidRule[] = []

  inputs.forEach((raw, index) => {
    const errors: string[] = []
    const name = raw.name.trim() || `规则 #${index + 1}`

    let cidr: ReturnType<typeof parseCidrStrict> | null = null
    if (!raw.cidr.trim()) {
      errors.push('CIDR 不能为空')
    } else {
      try {
        cidr = parseCidrStrict(raw.cidr)
      } catch (err) {
        errors.push((err as Error).message)
      }
    }

    const pStartText = String(raw.portStart).trim()
    const pEndText = String(raw.portEnd).trim()
    const ports = validatePortRange(pStartText, pEndText)
    const portStart = ports.portStart
    const portEnd = ports.portEnd
    errors.push(...ports.errors)

    let protocol: Protocol | null = null
    const protoUpper = raw.protocol.trim().toUpperCase()
    if (!protoUpper) {
      errors.push('协议不能为空')
    } else if (!PROTOCOLS.includes(protoUpper as Protocol)) {
      errors.push(`协议必须为 TCP / UDP / ANY，收到 “${raw.protocol}”`)
    } else {
      protocol = protoUpper as Protocol
    }

    const action = raw.action.trim()
    if (!action) errors.push('动作不能为空')

    if (errors.length > 0 || !cidr || protocol === null) {
      invalid.push({
        id: raw.id,
        index,
        name,
        errors,
        raw: {
          cidr: raw.cidr,
          portStart: raw.portStart,
          portEnd: raw.portEnd,
          protocol: raw.protocol,
          action: raw.action,
          enabled: raw.enabled,
        },
      })
      return
    }

    valid.push({
      id: raw.id,
      name,
      index,
      ipStart: cidr.start,
      ipEnd: cidr.end,
      prefix: cidr.prefix,
      cidrText: cidr.canonical,
      portStart,
      portEnd,
      protocol,
      action,
      enabled: raw.enabled,
    })
  })

  return { valid, invalid }
}

// ---------------------------------------------------------------------------
// 原子空间构建
// ---------------------------------------------------------------------------

function atomPrefix(start: number, end: number): number {
  // 块大小一定是 2 的幂（递归按中点切分）
  const size = (end - start + 1) >>> 0
  return 32 - Math.log2(size)
}

interface Range {
  start: number
  end: number
}

/**
 * 把一个原子块按目标区间 [lo, hi] 递归二分。
 * 返回的块两两互斥且仍按 CIDR 对齐；inside=true 的块（落在区间内）会标注。
 */
function splitAtom(
  atom: Range,
  lo: number,
  hi: number,
): Array<Range & { inside: boolean }> {
  // 整块在区间外
  if (atom.end < lo || atom.start > hi) {
    return [{ ...atom, inside: false }]
  }
  // 整块在区间内
  if (lo <= atom.start && atom.end <= hi) {
    return [{ ...atom, inside: true }]
  }
  // 相交但不完全包含：必须能继续二分（CIDR 块大小必为 2 的幂）
  const size = atom.end - atom.start + 1
  if (size <= 1) {
    throw new Error('不可再分的原子块出现部分相交，数据有误')
  }
  const half = size / 2
  const mid = (atom.start + half - 1) >>> 0
  const left = splitAtom({ start: atom.start, end: mid }, lo, hi)
  const right = splitAtom({ start: (mid + 1) >>> 0, end: atom.end }, lo, hi)
  return [...left, ...right]
}

/** 把一条 CIDR 范围插入既有原子集合，必要时按中点递归切割。 */
function insertRange(atoms: Range[], lo: number, hi: number): Range[] {
  const next: Range[] = []
  for (const atom of atoms) {
    if (atom.end < lo || atom.start > hi || (lo <= atom.start && atom.end <= hi)) {
      next.push(atom)
      continue
    }
    for (const piece of splitAtom(atom, lo, hi)) {
      next.push({ start: piece.start, end: piece.end })
    }
  }
  return next.sort((a, b) => a.start - b.start)
}

/**
 * 由所有参与分析的规则 CIDR 构建 IP 原子空间。
 * extra 可追加额外区间（如策略目标验证的目标 CIDR）：其边界同样参与切分，
 * 保证目标边界即使落在规则原子块内部也能被精确切开。
 */
export function buildIpAtoms(
  rules: NormalizedRule[],
  extra: Range[] = [],
): IpAtom[] {
  let atoms: Range[] = [{ start: 0, end: 0xffffffff }]
  for (const rule of rules) {
    atoms = insertRange(atoms, rule.ipStart, rule.ipEnd)
  }
  for (const range of extra) {
    atoms = insertRange(atoms, range.start, range.end)
  }
  return atoms.map((a) => ({ ...a, prefix: atomPrefix(a.start, a.end) }))
}

/** 由所有端口区间构建端口原子段，边界取所有区间端点；extra 同 buildIpAtoms。 */
export function buildPortAtoms(
  rules: NormalizedRule[],
  extra: Range[] = [],
): PortAtom[] {
  const boundaries = new Set<number>([0, 65536])
  for (const rule of rules) {
    boundaries.add(rule.portStart)
    boundaries.add(rule.portEnd + 1)
  }
  for (const range of extra) {
    boundaries.add(range.start)
    boundaries.add(range.end + 1)
  }
  const points = [...boundaries].sort((a, b) => a - b)
  const atoms: PortAtom[] = []
  for (let i = 0; i < points.length - 1; i++) {
    atoms.push({ start: points[i], end: points[i + 1] - 1 })
  }
  return atoms
}

/** 二分查找落在 [lo, hi] 内的原子下标（原子与规则同维且已排序）。 */
export function containedIndices<T extends { start: number; end: number }>(
  atoms: T[],
  lo: number,
  hi: number,
): number[] {
  const out: number[] = []
  for (let i = 0; i < atoms.length; i++) {
    if (atoms[i].start >= lo && atoms[i].end <= hi) out.push(i)
  }
  return out
}

/** 单个原子单元的报文空间大小 */
export function atomCellSize(ip: IpAtom, port: PortAtom): number {
  return (ip.end - ip.start + 1) * (port.end - port.start + 1)
}

/**
 * 在给定的原子空间上，按规则顺序登记每个单元 (ipIdx.portIdx.protoIdx)
 * 的首个命中者（valid 列表下标）。调序预览复用它对当前 / 候选顺序
 * 在同一套原子划分上各跑一次，从而逐单元对齐对比。
 */
export function buildOwnerMap(
  valid: NormalizedRule[],
  ipAtoms: IpAtom[],
  portAtoms: PortAtom[],
): Map<string, number> {
  const owner = new Map<string, number>()
  valid.forEach((rule, rulePos) => {
    const ipIdx = containedIndices(ipAtoms, rule.ipStart, rule.ipEnd)
    const portIdx = containedIndices(portAtoms, rule.portStart, rule.portEnd)
    const protoIdx = PROTO_INDEX.get(rule.protocol)!
    for (const ip of ipIdx) {
      for (const port of portIdx) {
        for (const proto of protoIdx) {
          const key = `${ip}.${port}.${proto}`
          if (!owner.has(key)) owner.set(key, rulePos)
        }
      }
    }
  })
  return owner
}

// ---------------------------------------------------------------------------
// 示例报文与区域合并
// ---------------------------------------------------------------------------

/** 原子块内的确定性代表地址：块内至少 4 个地址时取第 2 个，避免样例总是网络地址 */
export function exampleIp(atom: IpAtom): number {
  const size = atom.end - atom.start + 1
  return size >= 4 ? (atom.start + 1) >>> 0 : atom.start
}

function decodeKey(key: string): { ip: number; port: number; proto: number } {
  const [ip, port, proto] = key.split('.').map(Number)
  return { ip, port, proto }
}

function makePacket(
  key: string,
  ipAtoms: IpAtom[],
  portAtoms: PortAtom[],
  matched: NormalizedRule,
  kind: 'reachable' | 'shadowed',
): ExamplePacket {
  const { ip, port, proto } = decodeKey(key)
  return {
    srcIp: intToIpv4(exampleIp(ipAtoms[ip])),
    srcPort: portAtoms[port].start,
    protocol: CONCRETE_PROTOCOLS[proto],
    matchedRuleIndex: matched.index,
    matchedRuleName: matched.name,
    action: matched.action,
    kind,
  }
}

/** 合并相邻的整数区间 */
function mergeRanges(ranges: Array<{ start: number; end: number }>): Array<{
  start: number
  end: number
}> {
  const sorted = [...ranges].sort((a, b) => a.start - b.start)
  const merged: Array<{ start: number; end: number }> = []
  for (const range of sorted) {
    const last = merged[merged.length - 1]
    if (last && range.start <= last.end + 1) {
      last.end = Math.max(last.end, range.end)
    } else {
      merged.push({ ...range })
    }
  }
  return merged
}

/** 合并相邻且构成规范 CIDR 的 IP 原子块 */
export function mergeIpAtoms(indices: number[], ipAtoms: IpAtom[]): string[] {
  const sorted = [...new Set(indices)].sort((a, b) => ipAtoms[a].start - ipAtoms[b].start)
  const cidrs: string[] = []
  let i = 0
  while (i < sorted.length) {
    let start = ipAtoms[sorted[i]].start
    let size = ipAtoms[sorted[i]].end - start + 1
    let j = i
    // 尝试向块大小相同、地址连续且起始对齐 2*size 的右邻居翻倍
    while (j + 1 < sorted.length) {
      const next = ipAtoms[sorted[j + 1]]
      const doubled = size * 2
      if (next.start === ((start + size) >>> 0) && start % doubled === 0) {
        const expectedEnd = (start + doubled - 1) >>> 0
        if (next.end === expectedEnd) {
          size = doubled
          j++
          continue
        }
      }
      break
    }
    cidrs.push(formatCidr(start, 32 - Math.log2(size)))
    i = j + 1
  }
  return cidrs
}

function buildRegion(keys: Set<string>, ipAtoms: IpAtom[], portAtoms: PortAtom[]): RegionGroup[] {
  const byProto = new Map<number, { ips: Set<number>; ports: Set<number> }>()
  for (const key of keys) {
    const { ip, port, proto } = decodeKey(key)
    let group = byProto.get(proto)
    if (!group) {
      group = { ips: new Set(), ports: new Set() }
      byProto.set(proto, group)
    }
    group.ips.add(ip)
    group.ports.add(port)
  }
  const regions: RegionGroup[] = []
  for (const proto of [0, 1]) {
    const group = byProto.get(proto)
    if (!group) continue
    const cidrs = mergeIpAtoms([...group.ips], ipAtoms)
    const portRanges = mergeRanges(
      [...group.ports].map((p) => ({ start: portAtoms[p].start, end: portAtoms[p].end })),
    )
    const ipCount = cidrs.reduce((sum, cidr) => sum + 2 ** (32 - Number(cidr.split('/')[1])), 0)
    const portCount = portRanges.reduce((sum, r) => sum + (r.end - r.start + 1), 0)
    regions.push({
      protocol: CONCRETE_PROTOCOLS[proto],
      cidrs,
      portRanges,
      size: ipCount * portCount,
    })
  }
  return regions
}

// ---------------------------------------------------------------------------
// 主审计流程
// ---------------------------------------------------------------------------

interface RuleRuntime {
  rule: NormalizedRule
  ipIdx: number[]
  portIdx: number[]
  protoIdx: number[]
  declaredKeys: Set<string>
  ownedKeys: Set<string>
  /** key -> 遮蔽它的全部前序规则下标（规则在 valid 列表中的位置） */
  blockedBy: Map<string, Set<number>>
  ipSize: number
  portSize: number
}

function cellSize(ip: IpAtom, port: PortAtom): number {
  return (ip.end - ip.start + 1) * (port.end - port.start + 1)
}

export function audit(inputs: RuleInput[], now: Date = new Date()): AuditReport {
  const { valid, invalid } = validateRules(inputs)

  const ipAtoms = buildIpAtoms(valid)
  const portAtoms = buildPortAtoms(valid)

  const runtimes: RuleRuntime[] = valid.map((rule) => {
    const ipIdx = containedIndices(ipAtoms, rule.ipStart, rule.ipEnd)
    const portIdx = containedIndices(portAtoms, rule.portStart, rule.portEnd)
    const protoIdx = PROTO_INDEX.get(rule.protocol)!
    const ipSize = ipIdx.reduce((sum, i) => sum + (ipAtoms[i].end - ipAtoms[i].start + 1), 0)
    const portSize = portIdx.reduce(
      (sum, i) => sum + (portAtoms[i].end - portAtoms[i].start + 1),
      0,
    )
    return {
      rule,
      ipIdx,
      portIdx,
      protoIdx,
      declaredKeys: new Set(),
      ownedKeys: new Set(),
      blockedBy: new Map(),
      ipSize,
      portSize,
    }
  })

  /** key -> 首个命中该单元的规则（valid 列表下标） */
  const owner = new Map<string, number>()

  runtimes.forEach((rt, rulePos) => {
    for (const ip of rt.ipIdx) {
      for (const port of rt.portIdx) {
        for (const proto of rt.protoIdx) {
          const key = `${ip}.${port}.${proto}`
          rt.declaredKeys.add(key)
          const existing = owner.get(key)
          if (existing === undefined) {
            owner.set(key, rulePos)
            rt.ownedKeys.add(key)
          } else {
            let sources = rt.blockedBy.get(key)
            if (!sources) {
              sources = new Set<number>()
              rt.blockedBy.set(key, sources)
            }
            sources.add(existing)
          }
        }
      }
    }
  })

  const entries: AuditResultEntry[] = []

  runtimes.forEach((rt) => {
    const rule = rt.rule
    const declaredSize = rt.ipSize * rt.portSize * rt.protoIdx.length
    let effectiveSize = 0
    for (const key of rt.ownedKeys) {
      const { ip, port } = decodeKey(key)
      effectiveSize += cellSize(ipAtoms[ip], portAtoms[port])
    }

    // 遮蔽来源聚合并排序（贡献单元数多者在前）
    const sourceAgg = new Map<number, number>()
    for (const sources of rt.blockedBy.values()) {
      for (const pos of sources) {
        sourceAgg.set(pos, (sourceAgg.get(pos) ?? 0) + 1)
      }
    }
    const shadowSources: ShadowSource[] = [...sourceAgg.entries()]
      .map(([pos, cells]) => ({
        ruleIndex: runtimes[pos].rule.index,
        ruleName: runtimes[pos].rule.name,
        action: runtimes[pos].rule.action,
        cells,
      }))
      .sort((a, b) => b.cells - a.cells || a.ruleIndex - b.ruleIndex)

    // 示例报文：可达样例（确定性取序最小单元）
    let reachableExample: ExamplePacket | null = null
    if (rt.ownedKeys.size > 0) {
      const firstKey = [...rt.ownedKeys].sort()[0]
      reachableExample = makePacket(firstKey, ipAtoms, portAtoms, rule, 'reachable')
    }

    // 遮蔽样例：每个来源取一个确定性代表单元，最多 3 条且尽量覆盖不同来源
    const shadowedExamples: ExamplePacket[] = []
    const usedSources = new Set<number>()
    const blockedEntries = [...rt.blockedBy.entries()].sort((a, b) =>
      a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0,
    )
    // 第一轮：每个来源各取一个
    for (const sourcePos of [...sourceAgg.keys()].sort(
      (a, b) => (sourceAgg.get(b)! - sourceAgg.get(a)!) || a - b,
    )) {
      if (shadowedExamples.length >= 3) break
      const found = blockedEntries.find(
        ([, sources]) => sources.has(sourcePos) && !usedSources.has(sourcePos),
      )
      if (found) {
        shadowedExamples.push(
          makePacket(found[0], ipAtoms, portAtoms, runtimes[sourcePos].rule, 'shadowed'),
        )
        usedSources.add(sourcePos)
      }
    }

    const blockedCells = rt.blockedBy.size
    const declaredCells = rt.declaredKeys.size
    const effectiveCells = rt.ownedKeys.size
    // 完全遮蔽时，若没有任何单条前序规则独立遮蔽了全部单元，则属于多规则“共同覆盖”
    const collective =
      blockedCells > 0 &&
      effectiveCells === 0 &&
      ![...sourceAgg.values()].some((cells) => cells === blockedCells)

    let status: AuditEntry['status']
    if (declaredCells === 0) {
      status = 'empty'
    } else if (effectiveCells === 0) {
      status = 'fully-shadowed'
    } else if (blockedCells > 0) {
      status = 'partial-shadowed'
    } else {
      status = 'reachable'
    }

    entries.push({
      kind: 'valid',
      id: rule.id,
      index: rule.index,
      name: rule.name,
      cidrText: rule.cidrText,
      portStart: rule.portStart,
      portEnd: rule.portEnd,
      protocol: rule.protocol,
      action: rule.action,
      enabled: rule.enabled,
      status,
      declaredSize,
      effectiveSize,
      effectiveRatio: declaredSize === 0 ? 0 : effectiveSize / declaredSize,
      region: buildRegion(rt.ownedKeys, ipAtoms, portAtoms),
      shadowSources,
      blockedCells,
      declaredCells,
      effectiveCells,
      reachableExample,
      shadowedExamples,
      collectiveCover: collective,
    })
  })

  for (const bad of invalid) {
    const entry: AuditInvalidEntry = {
      kind: 'invalid',
      id: bad.id,
      index: bad.index,
      name: bad.name,
      errors: bad.errors,
      raw: bad.raw,
    }
    entries.push(entry)
  }

  entries.sort((a, b) => a.index - b.index)

  const validEntries = entries.filter((e): e is AuditEntry => e.kind === 'valid')
  const stats: AuditStats = {
    total: inputs.length,
    invalid: invalid.length,
    reachable: validEntries.filter((e) => e.status === 'reachable').length,
    partial: validEntries.filter((e) => e.status === 'partial-shadowed').length,
    fullyShadowed: validEntries.filter((e) => e.status === 'fully-shadowed').length,
    totalDeclaredSize: validEntries.reduce((s, e) => s + e.declaredSize, 0),
    totalEffectiveSize: validEntries.reduce((s, e) => s + e.effectiveSize, 0),
  }

  return {
    generatedAt: now.toISOString(),
    stats,
    entries,
  }
}

// ---------------------------------------------------------------------------
// 导入 / 导出
// ---------------------------------------------------------------------------

export function newRuleInput(index: number): RuleInput {
  return {
    id: makeId(),
    name: `规则 #${index + 1}`,
    cidr: '10.0.0.0/8',
    portStart: '0',
    portEnd: '65535',
    protocol: 'ANY',
    action: 'allow',
    enabled: true,
  }
}

export interface ImportResult {
  rules: RuleInput[]
  errors: string[]
}

/**
 * 解析粘贴的 JSON。支持：
 *   [ {cidr, portStart, ...}, ... ]
 *   { rules: [...] }
 *   本工具导出的完整报告 { entries: [...] }（仅还原可编辑字段）
 * 非法 CIDR / 端口不在这里抛出，而是作为规则进入列表后由审计标记为“非法不参与分析”。
 */
export function parseRulesJson(text: string): ImportResult {
  const errors: string[] = []
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (err) {
    return { rules: [], errors: [`JSON 解析失败：${(err as Error).message}`] }
  }

  let arr: unknown
  if (Array.isArray(data)) {
    arr = data
  } else if (data && typeof data === 'object') {
    const obj = data as Record<string, unknown>
    if (Array.isArray(obj.rules)) arr = obj.rules
    else if (Array.isArray(obj.entries)) {
      // 导出报告回填：entries 含 valid/invalid 两类
      arr = (obj.entries as unknown[]).map((e) => {
        const ent = e as Record<string, unknown>
        if (ent.kind === 'invalid') return { ...(ent.raw as object), name: ent.name }
        return ent
      })
    } else {
      return { rules: [], errors: ['根节点必须是数组，或含 rules / entries 字段的对象'] }
    }
  } else {
    return { rules: [], errors: ['根节点必须是数组或对象'] }
  }

  const rules: RuleInput[] = []
  ;(arr as unknown[]).forEach((item, i) => {
    if (!item || typeof item !== 'object') {
      errors.push(`第 ${i + 1} 条：不是对象，已跳过`)
      return
    }
    const o = item as Record<string, unknown>
    const str = (v: unknown): string => (v === undefined || v === null ? '' : String(v))
    const pickPort = (v: unknown): string | number =>
      typeof v === 'number' ? v : str(v)
    rules.push({
      id: typeof o.id === 'string' && o.id ? o.id : makeId(),
      name: str(o.name),
      cidr: str(o.cidr ?? o.cidrText),
      portStart: pickPort(o.portStart),
      portEnd: pickPort(o.portEnd),
      protocol: str(o.protocol).toUpperCase(),
      action: str(o.action),
      enabled: o.enabled === undefined ? true : Boolean(o.enabled),
    })
  })

  return { rules, errors }
}

export function exportReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2)
}

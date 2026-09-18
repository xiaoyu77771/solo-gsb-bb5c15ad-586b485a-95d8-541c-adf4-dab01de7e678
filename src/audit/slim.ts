/**
 * 无损精简分析。
 *
 * 对每条「已启用、合法且当前有有效流量」的规则 R 模拟**单独删除**，并在
 * 同一套 IPv4 原子块 × 端口原子段 × {TCP, UDP} 原子空间中逐单元比较删除
 * 前后每个报文的**最终动作**（首命中规则的动作；无任何规则覆盖即为
 * “未命中”，作为独立结果，绝不与某动作等同）：
 *
 *   - 删除前 R 是该单元的首命中者（即 R 的有效流量）；删除后该单元的
 *     新首命中者只可能是 R **之后**的规则 —— 前序规则若覆盖它，首命中
 *     本来就不会是 R。
 *   - 新首命中者动作 === R 的动作   → 被后续规则同动作接管（安全）
 *   - 新首命中者动作 !== R 的动作   → 最终动作改变（阻止删除）
 *   - 删除后无任何规则覆盖          → 未命中（阻止删除）
 *
 * 实现上只需在一次顺序扫描中为每个单元登记第一、第二命中者：R 的有效
 * 单元在“仅删除 R”后的新首命中者恰好就是第二命中者（或不存在）。
 * 原子划分由当前全部启用合法规则决定，删除模拟不重新切分，因此前后结果
 * 在完全相同的单元上对齐，不做任何覆盖比例近似。
 *
 * 每条可安全删除的规则都给出其原有效流量被**哪些后续规则**、在**哪些
 * 精确区域**（协议 → 连续端口段 × 规范 CIDR 行）以**相同动作**接管，
 * 每个接管分组附一个确定性、可复制的代表报文。
 */
import {
  activeRules,
  atomCellSize,
  buildExactRegions,
  buildIpAtoms,
  buildPortAtoms,
  concreteProtocolOf,
  containedIndices,
  exampleIp,
  protocolDimIndices,
  validateRules,
} from './engine'
import { intToIpv4 } from './iputil'
import type {
  ExactRegionGroup,
  IpAtom,
  PortAtom,
  Protocol,
  RuleInput,
} from './types'

export interface SlimPacket {
  srcIp: string
  srcPort: number
  protocol: Extract<Protocol, 'TCP' | 'UDP'>
}

/** 一组被某条后续规则以相同动作接管的原有效流量 */
export interface SlimTakeover {
  takeoverRuleId: string
  takeoverIndex: number
  takeoverName: string
  /** 接管动作；安全接管时与被删除规则动作一致 */
  action: string
  /** 精确接管区域：协议 → 连续端口段 × 规范 CIDR（行式，互斥且完备） */
  regions: ExactRegionGroup[]
  /** 接管的报文空间大小（各行合计，与逐单元统计精确一致） */
  size: number
  cells: number
  /** 确定性的可复制代表报文 */
  packet: SlimPacket
}

/** 阻止安全删除的区域：不同动作接管，或删除后未命中任何规则 */
export interface SlimBlocker {
  kind: 'different-action' | 'unmatched'
  /** different-action 时的新首命中规则；unmatched 时无 */
  takeoverRuleId?: string
  takeoverIndex?: number
  takeoverName?: string
  /** 新首命中动作（unmatched 时为空） */
  action?: string
  regions: ExactRegionGroup[]
  size: number
  cells: number
  packet: SlimPacket
}

export interface SlimSuggestion {
  ruleId: string
  ruleIndex: number
  ruleName: string
  /** 被分析规则自身的动作 */
  action: string
  /** 该规则当前有效（首命中）的报文空间大小与单元数 */
  effectiveSize: number
  effectiveCells: number
  /** 仅当全部有效单元都被后续规则以相同动作接管时为 true */
  safe: boolean
  /** 安全部分：按接管规则分组，各组区域互斥且合起来等于安全区域 */
  takeovers: SlimTakeover[]
  /** 阻止删除的部分：动作改变分组 + 未命中分组；为空才可安全删除 */
  blockers: SlimBlocker[]
}

export type SlimSkipReason = 'disabled' | 'invalid' | 'no-traffic'

export interface SlimSkipped {
  ruleId: string
  ruleIndex: number
  ruleName: string
  reason: SlimSkipReason
}

export interface SlimReport {
  generatedAt: string
  /** 逐条模拟删除的结果（已启用 + 合法 + 当前有有效流量），按规则序号排序 */
  suggestions: SlimSuggestion[]
  /** 未参与模拟删除的规则及原因 */
  skipped: SlimSkipped[]
  activeRuleCount: number
  invalidExcluded: number
  disabledExcluded: number
  safeCount: number
}

function decodeKey(key: string): [number, number, number] {
  const [ip, port, proto] = key.split('.').map(Number)
  return [ip, port, proto]
}

function packetOf(
  key: string,
  ipAtoms: IpAtom[],
  portAtoms: PortAtom[],
): SlimPacket {
  const [ip, port, proto] = decodeKey(key)
  return {
    srcIp: intToIpv4(exampleIp(ipAtoms[ip])),
    srcPort: portAtoms[port].start,
    protocol: concreteProtocolOf(proto),
  }
}

function sizeOfKeys(
  keys: Set<string>,
  ipAtoms: IpAtom[],
  portAtoms: PortAtom[],
): number {
  let size = 0
  for (const key of keys) {
    const [ip, port] = decodeKey(key)
    size += atomCellSize(ipAtoms[ip], portAtoms[port])
  }
  return size
}

/** 组内字典序最小单元作为确定性代表（与审计 / 调序预览选点规则一致） */
function firstKey(keys: Set<string>): string {
  let min: string | null = null
  for (const key of keys) {
    if (min === null || key < min) min = key
  }
  return min!
}

export function analyzeSlim(inputs: RuleInput[], now: Date = new Date()): SlimReport {
  const { valid, invalid } = validateRules(inputs)
  const active = activeRules(valid)
  const disabledRules = valid.filter((r) => !r.enabled)

  const ipAtoms = buildIpAtoms(active)
  const portAtoms = buildPortAtoms(active)

  // 预计算每条启用规则覆盖的原子下标集合，供逐单元归属判定
  const covers = active.map((rule) => ({
    ipIdx: new Set(containedIndices(ipAtoms, rule.ipStart, rule.ipEnd)),
    portIdx: new Set(containedIndices(portAtoms, rule.portStart, rule.portEnd)),
    protoIdx: protocolDimIndices(rule.protocol),
  }))

  // 一次顺序扫描：first = 首命中者；second = 第二命中者（删除首命中后的新首命中者）
  const first = new Map<string, number>()
  const second = new Map<string, number>()
  active.forEach((_rule, pos) => {
    const cover = covers[pos]
    for (const ip of cover.ipIdx) {
      for (const port of cover.portIdx) {
        for (const proto of cover.protoIdx) {
          const key = `${ip}.${port}.${proto}`
          if (!first.has(key)) first.set(key, pos)
          else if (!second.has(key)) second.set(key, pos)
        }
      }
    }
  })

  // 每条规则的有效单元（首命中归它的单元）
  const ownedByPos = new Map<number, Set<string>>()
  for (const [key, pos] of first) {
    let set = ownedByPos.get(pos)
    if (!set) {
      set = new Set()
      ownedByPos.set(pos, set)
    }
    set.add(key)
  }

  const suggestions: SlimSuggestion[] = []
  const skipped: SlimSkipped[] = []

  // 停用规则：不参与模拟删除
  for (const rule of disabledRules) {
    skipped.push({
      ruleId: rule.id,
      ruleIndex: rule.index,
      ruleName: rule.name,
      reason: 'disabled',
    })
  }
  // 非法规则：不参与模拟删除
  for (const bad of invalid) {
    skipped.push({
      ruleId: bad.id,
      ruleIndex: bad.index,
      ruleName: bad.name,
      reason: 'invalid',
    })
  }

  active.forEach((rule, pos) => {
    const owned = ownedByPos.get(pos)
    if (!owned || owned.size === 0) {
      // 合法且启用，但当前没有任何有效流量（被完全遮蔽等）：删除它本来就无流量可影响
      skipped.push({
        ruleId: rule.id,
        ruleIndex: rule.index,
        ruleName: rule.name,
        reason: 'no-traffic',
      })
      return
    }

    // 按删除后的结果分组：newPos -> 单元集合；-1 表示未命中
    const sameAction = new Map<number, Set<string>>()
    const diffAction = new Map<number, Set<string>>()
    const unmatched = new Set<string>()

    for (const key of owned) {
      const newPos = second.get(key)
      if (newPos === undefined) {
        unmatched.add(key)
      } else if (active[newPos].action === rule.action) {
        let set = sameAction.get(newPos)
        if (!set) {
          set = new Set()
          sameAction.set(newPos, set)
        }
        set.add(key)
      } else {
        let set = diffAction.get(newPos)
        if (!set) {
          set = new Set()
          diffAction.set(newPos, set)
        }
        set.add(key)
      }
    }

    const buildTakeover = (newPos: number, keys: Set<string>): SlimTakeover => {
      const t = active[newPos]
      return {
        takeoverRuleId: t.id,
        takeoverIndex: t.index,
        takeoverName: t.name,
        action: t.action,
        regions: buildExactRegions(keys, ipAtoms, portAtoms),
        size: sizeOfKeys(keys, ipAtoms, portAtoms),
        cells: keys.size,
        packet: packetOf(firstKey(keys), ipAtoms, portAtoms),
      }
    }

    const takeovers = [...sameAction.entries()]
      .map(([newPos, keys]) => buildTakeover(newPos, keys))
      .sort((a, b) => b.size - a.size || a.takeoverIndex - b.takeoverIndex)

    const blockers: SlimBlocker[] = [
      ...[...diffAction.entries()]
        .map(([newPos, keys]) => {
          const t = active[newPos]
          return {
            kind: 'different-action' as const,
            takeoverRuleId: t.id,
            takeoverIndex: t.index,
            takeoverName: t.name,
            action: t.action,
            regions: buildExactRegions(keys, ipAtoms, portAtoms),
            size: sizeOfKeys(keys, ipAtoms, portAtoms),
            cells: keys.size,
            packet: packetOf(firstKey(keys), ipAtoms, portAtoms),
          }
        }),
      ...(unmatched.size > 0
        ? [
            {
              kind: 'unmatched' as const,
              regions: buildExactRegions(unmatched, ipAtoms, portAtoms),
              size: sizeOfKeys(unmatched, ipAtoms, portAtoms),
              cells: unmatched.size,
              packet: packetOf(firstKey(unmatched), ipAtoms, portAtoms),
            },
          ]
        : []),
    ].sort((a, b) => b.size - a.size)

    suggestions.push({
      ruleId: rule.id,
      ruleIndex: rule.index,
      ruleName: rule.name,
      action: rule.action,
      effectiveSize: sizeOfKeys(owned, ipAtoms, portAtoms),
      effectiveCells: owned.size,
      safe: blockers.length === 0,
      takeovers,
      blockers,
    })
  })

  suggestions.sort((a, b) => a.ruleIndex - b.ruleIndex)
  skipped.sort((a, b) => a.ruleIndex - b.ruleIndex)

  return {
    generatedAt: now.toISOString(),
    suggestions,
    skipped,
    activeRuleCount: active.length,
    invalidExcluded: invalid.length,
    disabledExcluded: disabledRules.length,
    safeCount: suggestions.filter((s) => s.safe).length,
  }
}

/**
 * 首命中规则审计台 —— 类型定义
 *
 * 流量空间为三个维度的笛卡尔积：
 *   源 IPv4（CIDR 划分的原子块）× 源端口（区间边界划分的原子段）× 协议
 * 每条规则声明一个长方体区域；按列表顺序，首个覆盖某单元的规则即该单元的命中者。
 */

export type Protocol = 'TCP' | 'UDP' | 'ANY'
export type Action = string

/** UI / 导入中的规则原始形态 */
export interface RuleInput {
  id: string
  name: string
  cidr: string
  portStart: string | number
  portEnd: string | number
  protocol: string
  action: string
  enabled: boolean
}

/** 校验通过后的规范规则 */
export interface NormalizedRule {
  id: string
  name: string
  index: number
  ipStart: number
  ipEnd: number
  prefix: number
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  action: Action
  enabled: boolean
}

export interface InvalidRule {
  id: string
  index: number
  name: string
  errors: string[]
  raw: {
    cidr: string
    portStart: string | number
    portEnd: string | number
    protocol: string
    action: string
    enabled: boolean
  }
}

/** 由 CIDR 边界递归切割得到的 IP 原子块（始终对齐某个 CIDR 前缀） */
export interface IpAtom {
  start: number
  end: number
  prefix: number
}

export interface PortAtom {
  start: number
  end: number
}

export type StatusLevel = 'reachable' | 'partial-shadowed' | 'fully-shadowed' | 'invalid' | 'empty'

/** 遮蔽来源：单个单元可同时被多条更早的规则覆盖（共同覆盖） */
export interface ShadowSource {
  ruleIndex: number
  ruleName: string
  action: Action
  /** 该来源在此规则上贡献的单元数 */
  cells: number
}

/** 可复现的示例报文 */
export interface ExamplePacket {
  srcIp: string
  srcPort: number
  protocol: Exclude<Protocol, 'ANY'>
  matchedRuleIndex: number
  matchedRuleName: string
  action: Action
  /** reachable = 命中当前规则；shadowed = 命中的是更早的遮蔽规则 */
  kind: 'reachable' | 'shadowed'
}

/** 有效区域中按协议合并后的展示块 */
export interface RegionGroup {
  protocol: Exclude<Protocol, 'ANY'>
  cidrs: string[]
  portRanges: Array<{ start: number; end: number }>
  /** 该组覆盖的报文空间大小（IP 数 × 端口数） */
  size: number
}

export interface AuditEntry {
  kind: 'valid'
  id: string
  index: number
  name: string
  cidrText: string
  portStart: number
  portEnd: number
  protocol: Protocol
  action: Action
  enabled: boolean

  status: Exclude<StatusLevel, 'invalid'>
  /** 声明区域的报文空间大小 */
  declaredSize: number
  /** 首条命中语义下真正落到本规则的大小 */
  effectiveSize: number
  effectiveRatio: number

  region: RegionGroup[]
  shadowSources: ShadowSource[]
  /** 该规则被遮蔽的单元数（一个单元可被多个来源共同遮蔽，此为去重后的单元数） */
  blockedCells: number
  declaredCells: number
  effectiveCells: number

  reachableExample: ExamplePacket | null
  shadowedExamples: ExamplePacket[]
  /** 完全遮蔽且没有任何单条前序规则能独立遮蔽全部单元（即多规则共同覆盖） */
  collectiveCover: boolean
}

export interface AuditInvalidEntry {
  kind: 'invalid'
  id: string
  index: number
  name: string
  errors: string[]
  raw: InvalidRule['raw']
}

export type AuditResultEntry = AuditEntry | AuditInvalidEntry

export interface AuditStats {
  total: number
  invalid: number
  reachable: number
  partial: number
  fullyShadowed: number
  totalDeclaredSize: number
  totalEffectiveSize: number
}

export interface AuditReport {
  generatedAt: string
  stats: AuditStats
  entries: AuditResultEntry[]
}

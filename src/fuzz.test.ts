/**
 * 模糊对照测试：在缩小的报文空间（IP 取 /24 内 256 个地址，
 * 端口取 0..63，协议 TCP/UDP）上，用逐报文暴力首命中的结果
 * 与引擎审计结果逐项对照。
 */
import assert from 'node:assert'
import { audit, validateRules } from './audit/engine'
import type { RuleInput } from './audit/types'
import { ipv4ToInt } from './audit/iputil'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

/** 把随机块表示成规范 CIDR（限定 10.1.0.0/24 内，块大小为 2 的幂） */
function randomCidr(): string {
  const hostBits = rand(5) // /24 .. /28  (0..4 主机位，外加 /24 本身)
  const prefix = 24 + hostBits
  const size = 2 ** hostBits
  const base = rand(256 / size) * size
  return `10.1.0.${base}/${prefix}`
}

const PROTOS = ['TCP', 'UDP', 'ANY']
const ACTIONS = ['allow', 'deny']

function makeRules(n: number): RuleInput[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `f${i}`,
    name: `R${i}`,
    cidr: randomCidr(),
    portStart: String(rand(64)),
    portEnd: String(63), // 保证 start<=end 的概率大；下面再修正
    protocol: PROTOS[rand(3)],
    action: ACTIONS[rand(2)],
    enabled: true,
  })).map((r) =>
    Number(r.portStart) > Number(r.portEnd)
      ? { ...r, portStart: r.portEnd, portEnd: String(rand(64)) }
      : r,
  )
}

function bruteForce(rules: RuleInput[]) {
  const { valid } = validateRules(rules)
  // ownerCount[i] = 规则 i 在暴力枚举中拥有的报文数；blocked[targetPos][ownerPos] = 单元数
  const owned = new Array(valid.length).fill(0)
  const declared = new Array(valid.length).fill(0)
  const blockedFrom: Array<Map<number, number>> = valid.map(() => new Map())
  const blockedTotal = new Array(valid.length).fill(0)

  for (let ip = 0; ip < 256; ip++) {
    const ipNum = ipv4ToInt(`10.1.0.${ip}`)
    for (let port = 0; port < 64; port++) {
      for (let proto = 0; proto < 2; proto++) {
        const pName = proto === 0 ? 'TCP' : 'UDP'
        let first = -1
        for (let pos = 0; pos < valid.length; pos++) {
          const r = valid[pos]
          const ipOk = ipNum >= r.ipStart && ipNum <= r.ipEnd
          const portOk = port >= r.portStart && port <= r.portEnd
          const protoOk = r.protocol === 'ANY' || r.protocol === pName
          if (ipOk && portOk && protoOk) {
            if (first === -1) first = pos
            if (first !== -1 && pos !== first) {
              // 记录：pos 声明了该单元，但首个命中是 first
            }
          }
        }
        // 第二次遍历：统计声明/归属
        for (let pos = 0; pos < valid.length; pos++) {
          const r = valid[pos]
          const ipOk = ipNum >= r.ipStart && ipNum <= r.ipEnd
          const portOk = port >= r.portStart && port <= r.portEnd
          const protoOk = r.protocol === 'ANY' || r.protocol === pName
          if (ipOk && portOk && protoOk) {
            declared[pos]++
            if (first === pos) owned[pos]++
            else if (first !== -1) {
              blockedTotal[pos]++
              const m = blockedFrom[pos]
              m.set(first, (m.get(first) ?? 0) + 1)
            }
          }
        }
      }
    }
  }
  return { owned, declared, blockedFrom, blockedTotal, valid }
}

let rounds = 0
for (let round = 0; round < 400; round++) {
  const n = 1 + rand(7)
  const rules = makeRules(n)
  const report = audit(rules)
  const bf = bruteForce(rules)

  // 引擎 size 是在全端口 0..65535 空间；本测试规则端口都在 0..63、IP 在 /24，
  // 所以 size 与暴力计数（ip×port×proto）直接可比
  for (const e of report.entries) {
    if (e.kind !== 'valid') continue
    const pos = bf.valid.findIndex((r) => r.index === e.index)
    assert.ok(pos !== -1)
    const expectedOwned = bf.owned[pos]
    const expectedDeclared = bf.declared[pos]
    // 引擎有效 size：IP 数 × 端口数 × 协议数
    const engineSize = e.effectiveSize
    assert.equal(
      engineSize,
      expectedOwned,
      `round ${round} rule ${e.index}: effectiveSize ${engineSize} != brute ${expectedOwned}; rules=${JSON.stringify(rules)}`,
    )
    assert.equal(
      e.declaredSize,
      expectedDeclared,
      `round ${round} rule ${e.index}: declaredSize mismatch`,
    )
    const expectedStatus =
      expectedDeclared === 0
        ? 'empty'
        : expectedOwned === 0
          ? 'fully-shadowed'
          : bf.blockedTotal[pos] > 0
            ? 'partial-shadowed'
            : 'reachable'
    assert.equal(e.status, expectedStatus, `round ${round} rule ${e.index} status`)

    // 遮蔽来源
    for (const src of e.shadowSources) {
      const srcPos = bf.valid.findIndex((r) => r.index === src.ruleIndex)
      const expected = bf.blockedFrom[pos].get(srcPos) ?? 0
      assert.ok(expected > 0, `round ${round}: phantom shadow source`)
    }
    assert.equal(
      e.shadowSources.length,
      bf.blockedFrom[pos].size,
      `round ${round} rule ${e.index}: source count`,
    )
  }
  rounds++
}
console.log(`模糊对照 ${rounds} 轮全部通过 ✔`)

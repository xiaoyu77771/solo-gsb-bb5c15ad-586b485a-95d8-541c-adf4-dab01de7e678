/**
 * 无损精简的模糊对照测试：在缩小的报文空间（IP 取 10.1.0.0/24 内 256 个地址，
 * 端口取 0..63，协议 TCP/UDP）上，对随机规则集（含停用 / 非法规则）：
 *
 *   1. 逐报文暴力首命中，找出每条启用合法规则的“有效流量”；
 *   2. 对每条有有效流量的规则模拟删除：逐报文检查删除后的新首命中
 *      （后续规则 / 未命中），按 接管规则、动作是否相同、未命中 分组；
 *   3. 与 analyzeSlim 的输出逐项对照：safe 判定、分组、大小（逐报文展开
 *      精确区域）、代表报文暴力首命中核对、跳过原因（停用 / 非法 / 无流量）。
 */
import assert from 'node:assert'
import { validateRules } from './audit/engine'
import { analyzeSlim } from './audit/slim'
import type { RuleInput } from './audit/types'
import { ipv4ToInt, parseCidrStrict } from './audit/iputil'

function rand(n: number) {
  return Math.floor(Math.random() * n)
}

/** 10.1.0.0/24 内、/24../28 对齐的规范 CIDR（保证不跨出暴力盒子） */
function randomCidr(): string {
  const prefix = 24 + rand(5) // /24 .. /28
  const blockSize = 2 ** (32 - prefix)
  const base = rand(256 / blockSize) * blockSize
  return `10.1.0.${base}/${prefix}`
}

const PROTOS = ['TCP', 'UDP', 'ANY']
const ACTIONS = ['allow', 'deny']

function makeRules(n: number): RuleInput[] {
  return Array.from({ length: n }, (_, i) => {
    const bad = rand(7) === 0 // 约 1/7 非法
    const disabled = !bad && rand(6) === 0 // 约 1/6 停用（合法停用）
    // 端口限制在暴力空间 0..63 内，保证原子区域不跨出对照盒子
    const a = rand(64)
    const b = a + rand(64 - a)
    return {
      id: `s${i}`,
      name: `R${i}`,
      // CIDR 全部对齐在 10.1.0.0/24 盒子内，端口限制在 0..63
      cidr: bad && rand(2) === 0 ? '10.1.0.5/24' : randomCidr(),
      portStart: String(bad && rand(2) === 0 ? 99999 : a),
      portEnd: String(b),
      protocol: PROTOS[rand(3)],
      action: ACTIONS[rand(2)],
      enabled: !disabled,
    }
  })
}

type NRule = ReturnType<typeof validateRules>['valid'][number]

function matches(r: NRule, ip: number, port: number, proto: string): boolean {
  return (
    ip >= r.ipStart &&
    ip <= r.ipEnd &&
    port >= r.portStart &&
    port <= r.portEnd &&
    (r.protocol === 'ANY' || r.protocol === proto)
  )
}

/** 自上而下暴力首命中，返回命中规则在 active 中的下标 */
function firstHitIndex(active: NRule[], ip: number, port: number, proto: string): number {
  for (let k = 0; k < active.length; k++) {
    if (matches(active[k], ip, port, proto)) return k
  }
  return -1
}

/** 把精确区域展开成 `ip,port,proto` 报文集合 */
function expandRegions(
  regions: Array<{
    protocol: string
    rows: Array<{ portStart: number; portEnd: number; cidrs: string[] }>
  }>,
): Set<string> {
  const covered = new Set<string>()
  for (const reg of regions) {
    for (const row of reg.rows) {
      for (const cidr of row.cidrs) {
        const pc = parseCidrStrict(cidr)
        for (let ip = pc.start; ip <= pc.end; ip++) {
          for (let port = row.portStart; port <= row.portEnd; port++) {
            covered.add(`${ip},${port},${reg.protocol}`)
          }
        }
      }
    }
  }
  return covered
}

function assertSameCells(actual: Set<string>, expected: Set<string>, what: string) {
  assert.equal(actual.size, expected.size, `${what}：报文数不一致`)
  for (const cell of expected) assert.ok(actual.has(cell), `${what}：缺少 ${cell}`)
}

const G_START = ipv4ToInt('10.1.0.0')
const ROUNDS = 400

for (let round = 0; round < ROUNDS; round++) {
  const rules = makeRules(1 + rand(9))
  const { valid } = validateRules(rules)
  const active = valid.filter((r) => r.enabled)
  const ctx = `round ${round} rules=${JSON.stringify(rules)}`

  // 暴力：每个规则当前有效（首命中归它）的报文集合
  const ownedPackets = active.map(() => new Set<string>())
  for (let ip = G_START; ip <= G_START + 255; ip++) {
    for (let port = 0; port < 64; port++) {
      for (const proto of ['TCP', 'UDP']) {
        const h = firstHitIndex(active, ip, port, proto)
        if (h >= 0) ownedPackets[h].add(`${ip},${port},${proto}`)
      }
    }
  }

  const rep = analyzeSlim(rules)

  // 统计：停用 / 非法 / 无有效流量
  const disabledCount = valid.filter((r) => !r.enabled).length
  const invalidCount = rules.length - valid.length
  assert.equal(rep.disabledExcluded, disabledCount, `${ctx} disabledExcluded`)
  assert.equal(rep.invalidExcluded, invalidCount, `${ctx} invalidExcluded`)
  assert.equal(rep.activeRuleCount, active.length, `${ctx} activeRuleCount`)

  // 跳过原因
  for (const r of valid.filter((x) => !x.enabled)) {
    const sk = rep.skipped.find((s) => s.ruleId === r.id)
    assert.ok(sk, `${ctx} 停用规则 ${r.name} 应在 skipped`)
    assert.equal(sk!.reason, 'disabled', `${ctx} ${r.name} skip reason`)
  }

  // 逐规则对照模拟删除
  let expectedSafe = 0
  active.forEach((rule, pos) => {
    const owned = ownedPackets[pos]
    const sug = rep.suggestions.find((s) => s.ruleId === rule.id)
    if (owned.size === 0) {
      assert.ok(!sug, `${ctx} 无有效流量规则 ${rule.name} 不应有建议`)
      const sk = rep.skipped.find((s) => s.ruleId === rule.id)
      assert.ok(sk, `${ctx} ${rule.name} 应被跳过`)
      assert.equal(sk!.reason, 'no-traffic', `${ctx} ${rule.name} 跳过原因`)
      return
    }
    assert.ok(sug, `${ctx} 有有效流量规则 ${rule.name} 应有建议`)

    // 暴力模拟删除：仅移除该规则后逐报文重新首命中
    const rest = active.filter((_, k) => k !== pos)
    const byTarget = new Map<number, Set<string>>() // 新首命中在 rest 中的下标(-1=未命中)
    for (const cell of owned) {
      const [ipS, portS, proto] = cell.split(',')
      const ip = Number(ipS)
      const port = Number(portS)
      let h = -1
      for (let k = 0; k < rest.length; k++) {
        if (matches(rest[k], ip, port, proto)) {
          h = k
          break
        }
      }
      let set = byTarget.get(h)
      if (!set) {
        set = new Set()
        byTarget.set(h, set)
      }
      set.add(cell)
    }

    const expectedSame = [...byTarget.entries()].filter(
      ([h]) => h >= 0 && rest[h].action === rule.action,
    )
    const expectedDiff = [...byTarget.entries()].filter(
      ([h]) => h >= 0 && rest[h].action !== rule.action,
    )
    const expectedUnmatched = byTarget.get(-1)
    const expectedSafeNow = expectedDiff.length === 0 && !expectedUnmatched
    if (expectedSafeNow) expectedSafe++

    assert.equal(sug!.safe, expectedSafeNow, `${ctx} ${rule.name} safe 判定`)
    // 有效报文空间：所有接管/阻止分组的逐报文展开合计 = 暴力有效流量
    const allGroupPackets = new Set<string>()
    for (const t of sug!.takeovers) {
      const pset = expandRegions(t.regions)
      for (const c of pset) {
        assert.ok(!allGroupPackets.has(c), `${ctx} 分组区域互斥`)
        allGroupPackets.add(c)
      }
    }
    for (const b of sug!.blockers) {
      const pset = expandRegions(b.regions)
      for (const c of pset) {
        assert.ok(!allGroupPackets.has(c), `${ctx} 分组区域互斥`)
        allGroupPackets.add(c)
      }
    }
    assertSameCells(allGroupPackets, owned, `${ctx} ${rule.name} 全部区域合计=有效流量`)
    assert.equal(
      sug!.takeovers.length,
      expectedSame.length,
      `${ctx} ${rule.name} takeover 分组数`,
    )
    assert.equal(
      sug!.blockers.filter((b) => b.kind === 'different-action').length,
      expectedDiff.length,
      `${ctx} ${rule.name} diff 分组数`,
    )
    assert.equal(
      sug!.blockers.filter((b) => b.kind === 'unmatched').length,
      expectedUnmatched ? 1 : 0,
      `${ctx} ${rule.name} unmatched 分组数`,
    )

    // 逐接管分组：区域展开与暴力集合一致
    for (const [h, cells] of expectedSame) {
      const t = sug!.takeovers.find((x) => x.takeoverRuleId === rest[h].id)
      assert.ok(t, `${ctx} ${rule.name} 缺少对 ${rest[h].name} 的接管分组`)
      assert.equal(t!.action, rule.action)
      assertSameCells(expandRegions(t!.regions), cells, `${ctx} takeover ${rest[h].name}`)
      // 代表报文：删除前命中被删规则、删除后命中接管规则
      const pIp = ipv4ToInt(t!.packet.srcIp)
      const beforeHit = firstHitIndex(active, pIp, t!.packet.srcPort, t!.packet.protocol)
      assert.equal(active[beforeHit].id, rule.id, `${ctx} 代表报文删除前应命中被删规则`)
      const afterHit = firstHitIndex(rest, pIp, t!.packet.srcPort, t!.packet.protocol)
      assert.equal(rest[afterHit].id, rest[h].id, `${ctx} 代表报文删除后应命中接管规则`)
    }

    // 逐不同动作分组
    for (const [h, cells] of expectedDiff) {
      const b = sug!.blockers.find(
        (x) => x.kind === 'different-action' && x.takeoverRuleId === rest[h].id,
      )
      assert.ok(b, `${ctx} ${rule.name} 缺少对 ${rest[h].name} 的动作变化分组`)
      assert.equal(b!.action, rest[h].action)
      assertSameCells(expandRegions(b!.regions), cells, `${ctx} diff ${rest[h].name}`)
      const pIp = ipv4ToInt(b!.packet.srcIp)
      const afterHit = firstHitIndex(rest, pIp, b!.packet.srcPort, b!.packet.protocol)
      assert.equal(rest[afterHit].id, rest[h].id, `${ctx} 动作变化代表报文核对`)
    }

    // 未命中分组
    if (expectedUnmatched) {
      const b = sug!.blockers.find((x) => x.kind === 'unmatched')!
      assertSameCells(expandRegions(b.regions), expectedUnmatched, `${ctx} unmatched 区域`)
      const pIp = ipv4ToInt(b.packet.srcIp)
      assert.equal(
        firstHitIndex(rest, pIp, b.packet.srcPort, b.packet.protocol),
        -1,
        `${ctx} 未命中代表报文删除后确实无人命中`,
      )
      assert.equal(
        firstHitIndex(active, pIp, b.packet.srcPort, b.packet.protocol),
        pos,
        `${ctx} 未命中代表报文删除前命中被删规则`,
      )
    }
  })

  assert.equal(rep.safeCount, expectedSafe, `${ctx} safeCount`)
}

console.log(`无损精简模糊对照 ${ROUNDS} 轮全部通过 ✔`)

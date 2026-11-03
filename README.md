# v2-auth — v2one999 线上授权站

Cloudflare Pages 一体站：静态页是管理后台，`functions/` 是接口，KV 存授权与订阅。
设计定版见 [PLAN.md](./PLAN.md)。

## 功能
- 后台（`/`）：管理员密码登录 → 发码（预绑机器码）/ 直接开通 → 设备总表
  （机器码、备注、激活/到期、最近打开、拉取次数、状态）→ 停用/恢复/解绑/延期。
- 客户端接口：
  - `POST /api/challenge` 取 Attestation 挑战码
  - `POST /api/activate` 输码激活（可选 Key Attestation 验原装，见下）
  - `POST /api/claim` 后台直开后，用户点「我已付款」领取
  - `POST /api/validate` 每次打开校验（设备密钥 ES256 签名，或激活令牌）
  - `POST /api/subscription` 校验通过才下发订阅；订阅存 KV，超过 30 分钟
    才回上游懒刷新一次，没人打开就不拉。
- 完整性：激活时可验安卓 Key Attestation 证书链——挑战码、包名、APK
  签名证书摘要全对上才发令牌；改包/重打包必换签名，过不了。

## 本地跑
```bash
npm i
cp .dev.vars.example .dev.vars   # 填本地测试值（.dev.vars 已 gitignore）
npm run dev                      # http://127.0.0.1:8788
npm test                         # 全流程 24 项断言（需先 dev 起来）
```

## 上线（Cloudflare）
1. 在 Cloudflare 建 KV 命名空间，把 id 填进 `wrangler.toml`。
2. Pages 项目连接本仓库（构建输出目录 = `public`，无需构建命令）。
3. Pages 项目设置里绑定：KV 绑定名 `KV`；密钥变量：
   `ADMIN_PASSWORD`（后台登录密码）、`SESSION_SECRET`（随机长串）、
   `ADMIN_SECRET`（可选，脚本调管理接口用）、`SUB_URL`（订阅真实地址）、
   `EXPECTED_PACKAGE`、`EXPECTED_CERT_SHA256`（官方签名证书 SHA-256）、
   `ATTEST_REQUIRED=1`（客户端带 Attestation 后再开）、
   `ATTEST_ROOT_SHA256`（可选，真实设备认证链根证书指纹，首台真机激活后锁定）。
4. 绑定自有域名（pages.dev 在国内不稳，只作备用入口）。

## 注意
- `.dev.vars`、生产密钥永远不进仓库；订阅真实地址只存在于服务器密钥。
- KV 是最终一致性：停用最迟约 60 秒全球生效。

<br/>
<div align="center">

A curated list of awesome Node.js Security resources.

![#](https://badgen.net/badge/tools/30+/blue)
![#](https://badgen.net/badge/incidents/15+/red)
![#](https://badgen.net/badge/educational/8+/green)

[![liran_tal](https://img.shields.io/twitter/url/https/twitter.com/liran_tal.svg?style=social&label=Follow%20%40Liran%20Tal)](https://twitter.com/liran_tal)

<br/>

<hr/>

<p>
  <a href="https://nodejs-security.com">
    <img alt="Node.js Security" align="center" src="https://img.shields.io/badge/%F0%9F%A6%84-Learn%20Node.js%20Security%E2%86%92-gray.svg?colorA=5734F5&colorB=5734F5&style=flat" />
  </a>
</p>

![Screenshot 2024-09-12 at 20 14 27](https://github.com/user-attachments/assets/586f3151-eed9-4542-92f1-de9237f6783c)

<p>
  Learn Node.js Secure Coding techniques and best practices from <a href="https://www.lirantal.com">Liran Tal</a>
</p>

</div>
<br/>

# Contents

- [Tools](#tools)
  - [Web Framework Hardening](#web-framework-hardening)
  - [Static Code Analysis](#static-code-analysis)
  - [Dynamic Application Security Testing](#dynamic-application-security-testing)
  - [Input/Output Validation](#input-validation--output-encoding)
  - [Secure Composition](#secure-composition)
  - [CSRF](#csrf)
  - [Vulnerabilities and Security Advisories](#vulnerabilities-and-security-advisories)
  - [Security Hardening](#security-hardening)
- [Data Sources](#data-sources)
- [Security Incidents](#security-incidents)
- [Educational](#educational)
  - [Hacking Playground](#hacking-playground)
  - [Articles](#articles)
  - [Research Papers](#research-papers)
  - [Books](#books)
  - [Roadmaps](#roadmaps)
- [Companies](#companies)

# Tools

## Web Framework Hardening
- [Helmet](https://www.npmjs.com/package/helmet) - Helmet helps you secure your Express apps by setting various HTTP headers.
- [koa-helmet](https://www.npmjs.com/package/koa-helmet) - koa-helmet helps you secure your Koa apps by setting various HTTP headers.
- [blankie](https://github.com/nlf/blankie) - CSP plugin for [hapi](https://github.com/hapijs/hapi).
- [fastify-helmet](https://github.com/fastify/fastify-helmet) - fastify-helmet helps you secure your [fastify](https://www.fastify.io/) apps by setting important security headers.
- [nuxt-security](https://github.com/Baroshem/nuxt-security) - 🛡 Security Module for Nuxt based on OWASP Top 10 and Helmet.
- [reporting-api](https://github.com/wille/reporting-api) - Setup and collect CSP, Reporting API v0 and v1 reports to reliabily parse them to be processed by the user

## GitHub Actions and CI/CD Security
- [New dependencies advisor](https://github.com/marketplace/actions/new-dependencies-advisor) - GitHub Action adding comments to pull requests with package health information about newly added npm dependencies.
- [OpenSSF Scorecard Monitor](https://github.com/marketplace/actions/openssf-scorecard-monitor) - Simplify OpenSSF Scorecard tracking in your organization with automated markdown and JSON reports, plus optional GitHub issue alerts.

## Static Code Analysis
- [eslint-plugin-security](https://www.npmjs.com/package/eslint-plugin-security) - ESLint rules for Node Security. This project will help identify potential security hotspots, but finds a lot of false positives which need triage by a human.
- [tslint-plugin-security](https://www.npmjs.com/package/tslint-config-security) - TSLint rules for Node Security. This project will help identify potential security hotspots, but finds a lot of false positives which need triage by a human.
- [safe-regex](https://www.npmjs.com/package/safe-regex) - detect potentially catastrophic exponential-time regular expressions by limiting the star height to 1.
- [vuln-regex-detector](https://www.npmjs.com/package/vuln-regex-detector) - This module lets you check a regex for vulnerability. In JavaScript, regular expressions (regexes) can be "vulnerable": susceptible to catastrophic backtracking. If your application is used on the client side, this can be a performance issue. On the server side, this can expose you to Regular Expression Denial of Service (REDOS).
- [regolith](https://github.com/JakeRoggenbuck/regolith) - Regex library for TypeScript made to prevent ReDoS attacks I made TypeScript bindings for the Rust Regex library to prevent Regular Expression Denial of Service attacks.
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevents you from committing secrets and credentials into git repositories.
- [DevSkim](https://github.com/Microsoft/DevSkim) - DevSkim is a set of IDE plugins and rules that provide security "linting" capabilities. Also has support for CLI so it can be integrated into CI/CD pipeline.
- [ban-sensitive-files](https://github.com/bahmutov/ban-sensitive-files) - Checks filenames to be committed against a library of filename rules to prevent storing sensitive files in Git. Checks some files for sensitive contents (for example authToken inside .npmrc file).
- [NodeJSScan](https://github.com/ajinabraham/nodejsscan) - A static security code scanner for Node.js applications. Including neat UI that can point where the issue is and how to fix it.
- [NodeSecure CLI](https://github.com/NodeSecure/cli) - Node.js CLI that allow you to deeply analyze the dependency tree of a given npm package or a directory.
- [Trust But Verify](https://github.com/verifynpm/tbv) - TBV compares an npm package with its source repository to ensure the resulting artifact is the same.
- [lockfile-lint](https://github.com/lirantal/lockfile-lint) - lint lockfiles for improved security and trust policies to keep clean from malicious package injection and other insecure configurations.
- [pkgsign](https://github.com/RedpointGames/pkgsign) - A CLI tool for signing and verifying npm and yarn packages.
- [semgrep](https://semgrep.dev) - Open-source, offline, easy-to-customize static analysis for many languages. Some others on this list (NodeJSScan) use semgrep as their engine.
- [npm-scan](https://github.com/spaceraccoon/npm-scan) - An extensible, heuristic-based vulnerability scanning tool for installed npm packages.
- [js-x-ray](https://github.com/NodeSecure/js-x-ray) - JavaScript and Node.js SAST scanner capable of detecting various well-known malicious code patterns (Unsafe import, Unsafe stmt, Unsafe RegEx, encoded literals, minified and obfuscated codes).
- [cspscanner](https://cspscanner.com/) - CSP Scanner helps developers and security experts to easily inspect and evaluate a site’s Content Security (CSP).
- [eslint-plugin-anti-trojan-source](https://github.com/lirantal/eslint-plugin-anti-trojan-source) - ESLint plugin to detect and prevent Trojan Source attacks from entering your codebase.
- [sdc-check](https://github.com/mbalabash/sdc-check) - Small tool to inform you about potential risks in your project dependencies list
- [fix-lockfile-integrity](https://github.com/yoavain/fix-lockfile-integrity) - A CLI tool to fix weak integrity hash (sha1) to a more secure integrity hash (sha512) in your npm lockfile.
- [Bearer](https://github.com/Bearer/bearer) - A CLI tool to find and help you fix security and privacy risks in your code according to OWASP Top 10.
- [GuardDog](https://github.com/DataDog/guarddog) - GuardDog is a CLI tool to Identify malicious PyPI and npm packages

## Dynamic Application Security Testing

- [PurpleTeam](https://purpleteam-labs.com) - A security regression testing SaaS and CLI, perfect for inserting into your build pipelines. You don’t need to write any tests yourself. purpleteam is smart enough to know how to test, you just need to provide a Job file which tells purpleteam what you want tested.

## Input Validation & Output Encoding
- [node-esapi](https://www.npmjs.com/package/node-esapi) - node-esapi is a minimal port of the ESAPI4JS (Enterprise Security API for JavaScript) encoder.
- [escape-html](https://www.npmjs.com/package/escape-html) - Escape string for use in HTML.
- [js-string-escape](https://www.npmjs.com/package/js-string-escape) - Escape any string to be a valid JavaScript string literal between double quotes or single quotes.
- [validator](https://github.com/chriso/validator.js) - An npm library of string validators and sanitizers.
- [xss-filters](https://www.npmjs.com/package/xss-filters) - Just sufficient output filtering to prevent XSS!
- [DOMPurify](https://github.com/cure53/DOMPurify) - a DOM-only, super-fast, uber-tolerant XSS sanitizer for HTML, MathML and SVG.
- [envalid](https://github.com/af/envalid) - Envalid is a small library for validating and accessing environment variables in Node.js.
- [data-guardian](https://www.npmjs.com/package/data-guardian) - data-guardian is a tiny, highly customizable lib which can mask sensitive data in arbitrary entities and can help with [OWASP Protect Data everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere).

## Secure Composition
- [pug-plugin-trusted-types](https://www.npmjs.com/package/pug-plugin-trusted-types) - Pug template plugin makes it easy to securely compose HTML from untrusted inputs and provides CSP & CSRF [automagic](https://www.npmjs.com/package/pug-plugin-trusted-types#hdr-automagic).
- [safesql](https://www.npmjs.com/package/safesql) - A tagged template (<code>mysql\`...\`</code>) that understands [Postgres](https://www.npmjs.com/package/safesql#pg)'s & [MySQL](https://www.npmjs.com/package/safesql#mysql)'s query grammar to prevent [SQL injection](https://www.oreilly.com/library/view/securing-node-applications/9781491982426/ch01.html#idm140399946848800).
- [sh-template-tag](https://www.npmjs.com/package/sh-template-tag) - A tagged template (<code>sh\`...\`</code>) that understands Bash syntax so prevents [shell injection](https://www.oreilly.com/library/view/securing-node-applications/9781491982426/ch01.html#idm140399951358480).

## CSRF
- [csurf](https://www.npmjs.com/package/csurf) - Node.js CSRF protection middleware.
- [crumb](https://github.com/hapijs/crumb) - CSRF crumb generation and validation for [hapi](https://github.com/hapijs/hapi).
- [fastify-csrf](https://github.com/fastify/fastify-csrf) - A plugin for adding CSRF protection to [fastify](https://www.fastify.io).

## Vulnerabilities and Security Advisories
- [npq](https://github.com/lirantal/npq) - Safely install packages with npm or yarn by auditing them as part of your install process.
- [snyk](https://www.npmjs.com/package/snyk) - Snyk helps you find, fix and monitor known vulnerabilities in Node.js npm, Ruby and Java dependencies, both on an ad hoc basis and as part of your CI (Build) system.
- [node-release-lines](https://www.npmjs.com/package/node-release-lines) - Introspection API for Node.js release metadata. Provides information about release lines, their relative status along with details of each release.
- [auditjs](https://github.com/OSSIndex/auditjs) - Audits an NPM package.json file to identify known vulnerabilities using the [OSSIndex](https://ossindex.sonatype.org/rest).
- [npm-audit](https://docs.npmjs.com/cli/audit) - Runs a security audit based on your package.json using npm.
- [npm-audit-resolver](https://www.npmjs.com/package/npm-audit-resolver) - Manage npm-audit results, including options to ignore specific issues in clear and auditable way.
- [gammaray](https://github.com/nearform/gammaray) - Runs a security audit based on your package.json using the [Node.js Security Working Group vulnerability data](https://github.com/nodejs/security-wg/).
- [patch-package](https://www.npmjs.com/package/patch-package) - Allows app authors to create fixes for npm dependencies (in node_modules) without forking or waiting for merged PRs, by creating and applying patches.
- [check-my-headers](https://github.com/UlisesGascon/check-my-headers) - Fast and simple way to check any HTTP Headers.
- [is-website-vulnerable](https://github.com/lirantal/is-website-vulnerable/) - finds publicly known security vulnerabilities in a website's frontend JavaScript libraries.
- [joi-security](https://github.com/Saluki/joi-security/) - Detect security flaws in Joi validation schemas.
- [confused](https://github.com/visma-prodsec/confused) - Tool to check for dependency confusion vulnerabilities in multiple package management systems. See [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610) for reference on the reasoning for this tool.
- [nodejs-cve-checker](https://github.com/nodejs/nodejs-cve-checker) - A simple tool that validates CVEs were published to NVD after a Node.js Security Release.
- [zizmor](https://github.com/zizmorcore/zizmor) - Static analysis for GitHub Actions and CI/CD workflows.

## Security Hardening
- [hijagger](https://github.com/firefart/hijagger) - Checks all maintainers of all npm and PyPI packages for hijackable packages through domain re-registration.
- [snync](https://github.com/snyk-labs/snync) - Mitigate security concerns of Dependency Confusion supply chain security risks.
- [NopPP - No Prototype Pollution](https://github.com/snyk-labs/nopp) - Tiny helper to protect against Prototype Pollution vulnerabilities in your application regardless if they introduced in your own code or in 3rd-party code.
- [anti-trojan-source](https://github.com/lirantal/anti-trojan-source) - Detect trojan source attacks that employ unicode bidi attacks to inject malicious code.
- [express-limiter](https://www.npmjs.com/package/express-limiter) - Rate limiting middleware for Express applications built on redis.
- [limits](https://www.npmjs.com/package/limits) - Simple express/connect middleware to set limit to upload size, set request timeout etc.
- [rate-limiter-flexible](https://www.npmjs.com/package/rate-limiter-flexible) - Fast, flexible and friendly rate limiter by key and protection from DDoS and brute force attacks in process Memory, Cluster, Redis, MongoDb, MySQL, PostgreSQL at any scale. Express and Koa examples included.
- [tor-detect-middleware](https://github.com/UlisesGascon/tor-detect-middleware) Tor detect middleware for express
- [express-enforces-ssl](https://github.com/hengkiardo/express-enforces-ssl) Enforces SSL for Express based Node.js projects. It is however highly advised that you handle SSL and global HTTP rules in a front proxy.
- [bourne](https://github.com/hapijs/bourne) `JSON.parse()` drop-in replacement with prototype poisoning protection.
- [fastify-rate-limit](https://github.com/fastify/fastify-rate-limit) A low overhead rate limiter for your routes.
- [secure-json-parse](https://github.com/fastify/secure-json-parse) `JSON.parse()` drop-in replacement with prototype poisoning protection.
- [express-brute](https://github.com/AdamPflug/express-brute) A brute-force protection middleware for express routes that rate-limits incoming requests, increasing the delay with each request in a fibonacci-like sequence.
- [allowed-scripts](https://www.npmjs.com/package/@lavamoat/allow-scripts) Execute allowed `npm install` lifecycle scripts.
- [ses](https://github.com/endojs/endo/tree/master/packages/ses#ses) A shim for Hardened JavaScript, a language mode that mitigates prototype pollution attacks and supports safely confining multiple tenants in a single JavaScript realm, endowing each other with hardened API objects.
- [lavamoat](https://github.com/lavamoat/lavamoat) Mitigates supply chain attacks using `ses` to confine third-party dependencies and limit their access to host powers based on policies generated by trust-on-first-use static analysis.
- [moddable](https://www.moddable.com/) Implements Hardened JavaScript as the security model for embedded systems.
- [is-my-node-vulnerable](https://github.com/RafaelGSS/is-my-node-vulnerable) - package that checks if your Node.js installation is vulnerable to known security vulnerabilities.
- [@lavamoat/preinstall-always-fail](https://www.npmjs.com/package/@lavamoat/preinstall-always-fail) - npm package to assert if preinstall or postinstall scripts are running in your npm or yarn workflows.
- [are-scripts-enabled](https://www.npmjs.com/package/are-scripts-enabled) - npm package to assert if preinstall or postinstall scripts are running in your npm or yarn workflows.

# Data Sources

- [resource](https://nodejs.org/dist/index.json) - A structured list of all the Node.js versions, the binary builds, the dependencies they include (npm, zlib, openssl) along with their versions, whether the release is a security release and whether it is an LTS.
- [resource](https://github.com/nodejs/security-wg/tree/main/vuln/core) - The `nodejs/secuirty-wg` GitHub repository maintains a `/vuln/core` directory with all the CVEs applied to Node.js runtime versions.

# Security Incidents

## Protestware supply chain security issues

The following is a list of known protestware spanning across other ecosystems too:
- [PyPI package author of atomicwrites deletes his own code](https://www.bleepingcomputer.com/news/security/pypi-mandates-2fa-for-critical-projects-developer-pushes-back/) 
- [left-pad](https://qz.com/646467/how-one-programmer-broke-the-internet-by-deleting-a-tiny-piece-of-code/)
- `event-source-polyfill`, Mariusz Nowak and their `es5-ext`, Evan Jacobs and their `styled-components`, [node-ipc](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/), `peacenotwar`, [nestjs-pino](https://socket.dev/npm/package/nestjs-pino/files/3.1.1/postinstall.js) - all with regards to the Russian-Ukraine crisis.
- The [Open Souce Peace](https://github.com/open-source-peace/protestware-list) organization maintains a list of identified protestware incidents.

Articles covering the topics around protestware are:
- [2022's Techcrunch protestware review](https://techcrunch.com/2022/07/27/protestware-code-sabotage/)
- [2022's Snyk protestware types](https://snyk.io/blog/protestware-open-source-types-impact/)

## npm and JavaScript specific security incidents and supply chain security issues

Collection of security incidents that happened in the Node.js, JavaScript and npm related communities with supporting articles:

| Date              | Name                                                                                                                                                            | Reference Links                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2025 Sep 15  | Shai-Hulud npm package malware | [Snyk](https://snyk.io/blog/embedded-malicious-code-in-tinycolor-and-ngx-bootstrap-releases-on-npm/), [ReversingLabs](https://www.reversinglabs.com/blog/shai-hulud-worm-npm?utm_source=newsletter.danielmiessler.com&utm_medium=newsletter&utm_campaign=unsupervised-learning-no-498&_bhlid=1aa82504dd754b12c5b653c6fe6b1cd46b6e9d5a), [Aikido](https://www.aikido.dev/blog/bugs-in-shai-hulud-debugging-the-desert)
| 2025 Sep 8   | Qix maintainer compromised via phishing campaign causing malware in debug chalk and many other packages | [Snyk](https://snyk.io/blog/npm-supply-chain-attack-via-open-source-maintainer-compromise/)
| 2025 Aug 27  | Nx package malicious version compromise and AI coding tools weaponization of LLM and agents | [Snyk](https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/)
| 2025 Jul 25  | Toptal packages were compromised leading to GitHub Token theft and systems destroyed | [Arstechnica](https://arstechnica.com/security/2025/07/open-source-repositories-are-seeing-a-rash-of-supply-chain-attacks/)
| 2025 Jul 19  | ESLint Config Prettier maintainers get compromised, spread malware and infect other maintainers too | [Snyk](https://snyk.io/blog/maintainers-of-eslint-prettier-plugin-attacked-via-npm-supply-chain-malware/), [Socket](https://socket.dev/blog/npm-phishing-campaign-leads-to-prettier-tooling-packages-compromise), [Safedep](https://safedep.io/eslint-config-prettier-major-npm-supply-chain-hack/)
| 2025 Jun 25  | BeaverTail North Korean group drops 35 npm malware packages | [Socket](https://socket.dev/blog/north-korean-contagious-interview-campaign-drops-35-new-malicious-npm-packages)
| 2025 Jun 12  | npm package `@react-native-aria/focus` and other `@react-native-area` namespace packages were found to be malicious | [Aikido](https://www.aikido.dev/blog/supply-chain-attack-on-react-native-aria-ecosystem), [Bleeping Computer](https://www.bleepingcomputer.com/news/security/supply-chain-attack-hits-gluestack-npm-packages-with-960k-weekly-downloads/amp/)
| 2025 May 15  | `os-info-checker-es6` npm package leverages unicode steganography in Google calendar as command and control | [Veracode](https://www.veracode.com/resources/sophisticated-npm-attack-leveraging-unicode-steganography-and-google-calendar-c2)
| 2025 May 8   | Package rand-user-agent with 45,000 downloads compromised in supply chain attack for malicious RAT | [Aikido](https://www.aikido.dev/blog/catching-a-rat-remote-access-trojian-rand-user-agent-supply-chain-compromise)
| 2025 May 7   | Malicious npm Packages Infect 3,200+ Cursor Users With Backdoor | [Socket](https://socket.dev/blog/malicious-npm-packages-hijack-cursor-editor-on-macos)
| 2025 May 2   | Typosquatting popular .NET, Python and other package names | [Socket](https://socket.dev/blog/npm-targeted-by-malware-campaign-mimicking-familiar-library-names)
| 2025 Apr 15  | Russian hackers typosquat express-exp | [Safety](https://www.getsafety.com/blog-posts/russian-hackers-manipulate-npm-to-make-realistic-packages)
| 2025 Apr 10  | pdf-to-office malicious npm package | [ReversingLabs](https://www.reversinglabs.com/blog/atomic-and-exodus-crypto-wallets-targeted-in-malicious-npm-campaign)
| 2025 Apr 5   | North Korean Hackers Deploy BeaverTail Malware via 11 Malicious npm Packages | [socket](https://socket.dev/blog/lazarus-expands-malicious-npm-campaign-11-new-packages-add-malware-loaders-and-bitbucket)
| 2025 Mar 26  | Malicious packages `ethers-provider2` and `ethers-providerz` | [ReversingLabs](https://www.reversinglabs.com/blog/malicious-npm-patch-delivers-reverse-shell)
| 2025 Mar 11  | North Korean Lazarus group targets npm packages  is-buffer-validator, yoojae-validator, event-handle-package, array-empty-validator, react-event-dependency, and auth-validator | [socket](https://socket.dev/blog/lazarus-strikes-npm-again-with-a-new-wave-of-malicious-packages)
| 2025 Feb 26  | Malicious Code Hidden in NPM Packages | [cycode](https://cycode.com/blog/malicious-code-hidden-in-npm-packages/)
| 2025 Jan 14  | npm command confusion | [Checkmarx](https://checkmarx.com/blog/npm-command-confusion/)
| 2025 Jan 13  | Typosquatted packages for Chalk and Chokidar harbor backdoor trojans | [socket](https://socket.dev/blog/kill-switch-hidden-in-npm-packages-typo-squatting-chalk-and-chokidar)
| 2024 Dec 20  | `@rspack/core` and `@rspack/cli` at 400k weekly downloads were compromised due to npm token theft and used to publish malicious packages for monero cryptocurrency mining | [rspack release notes](https://github.com/web-infra-dev/rspack/releases/tag/v1.1.8), [sonatype](https://www.sonatype.com/blog/npm-packages-rspack-vant-compromised-blocked-by-sonatype), [Socket](https://socket.dev/blog/rspack-supply-chain-attack)
| 2024 Dec 11  | Malicious npm Package `@typescript-eslint/eslint-plugin` exfiltrates data in typosquatting attack | [Socket](https://socket.dev/blog/malicious-npm-package-typosquats-popular-typescript-eslint-plugin)
| 2024 Dec 3   | Supply Chain Attack Detected in Solana's web3.js Library `@solana/web3.js` | [Socket](https://socket.dev/blog/supply-chain-attack-solana-web3-js-library)
| 2024 Nov 12  |  "node-request-ip", "request-ip-check" and "request-ip-validator" are fake IP checker utilities on npm target cryptocurrency and install trojans | [sonatype](https://www.sonatype.com/blog/fake-ip-checker-utilities-on-npm-are-crypto-stealers)
| 2024 Oct 31  | Lottie Player npm package compromised for crypto wallet theft | [Snyk](https://snyk.io/blog/lottie-player-npm-package-compromised-crypto-wallet-theft/)
| 2024 Oct 31  | Typosquat campaign targeting Puppeteer, Bignum.js, and some 137 other cryptocurrency libraries | [Phylum](https://blog.phylum.io/supply-chain-security-typosquat-campaign-targeting-puppeteer-users/)
| 2024 Oct 28  | Dependency confusion campaign used in an npm supply chain security leveraged to breach Fortune 500 company | https://www.landh.tech/blog/20241028-hidden-supply-chain-links/
| 2024 Oct 4   | `lodasher`, `them4on`, `laodasher` counterfeit npm packages aimed to backdoor Windows users with a modified AnyDesk binary | [Sonatype](https://www.sonatype.com/blog/counterfeit-lodash-attack-leverages-anydesk-to-target-windows-users)
| 2024 Jul 16  | `string-width-cjs` and other Suspicious Maintainer Unveils Threads of npm Supply Chain Attack | [Snyk](https://snyk.io/blog/threads-of-npm-supply-chain-attack/)
| 2024 Jul 11  | `noblox-ts` starjacking and QuasarRAT on npm | [stacklok](https://stacklok.com/blog/destroyloneliness-npm-starjacking-attack-on-roblox-nodejs-library-delivers-quasarrat)
| 2024 Jun 17  | `ua-parser-js` switches to AGPL+commercial in "rug pull" move | [Adventures in Nodeland](https://adventures.nodeland.dev/archive/what-happens-when-a-major-npm-library-goes/)
| 2024 Jun 11  | `cors-parser` npm package hides cross-platform backdoor in PNG files | [Sonatype](https://www.sonatype.com/blog/cors-parser-npm-package-hides-cross-platform-backdoor-in-png-files)
| 2024 Jun 03  | npm regsitry cache poisoning attack | [landh.tech](https://www.landh.tech/blog/20240603-npm-cache-poisoning/)
| 2024 Apr 26   | Fake job interviews target developers with new Python backdoor | [Bleeping Computer](https://www.bleepingcomputer.com/news/security/fake-job-interviews-target-developers-with-new-python-backdoor/)
| 2024 Apr 16 | Tea tokens and developers abusing OSS infrastructure for monetization | [Sonatype](https://www.sonatype.com/blog/devs-flood-npm-with-10000-packages-to-reward-themselves-with-tea-tokens)
| 2024 Feb 6    | noblox.js-proxy-server malicious npm Package Masquerades as Noblox.js, Targeting Roblox Users for Data Theft | [Socket](https://socket.dev/blog/malicious-npm-package-masquerades-as-noblox-js)
| 2024 Jan 25   | npm flooded with 748 packages that store movies | [Sonatype](https://blog.sonatype.com/npm-flooded-with-748-packages-that-store-movies)
| 2024 Jan 3    | An `everything` package with a registry-wide dependencies prevents from packages to be unpublished | [SC Media](https://www.scmagazine.com/news/npm-registry-prank-leaves-developers-unable-to-unpublish-packages)
| 2023 Dec 14   | Ledger supply chain security attack introducing crypto drainer malware (@ledgerhq/connect-kit) | [Sonatype](https://blog.sonatype.com/decrypting-the-ledger-connect-kit-compromise-a-deep-dive-into-the-crypto-drainer-attack), Tweets [1](https://twitter.com/Neodyme/status/1735337711555285261) [2](https://twitter.com/Ledger/status/1735370531224834430) [3](https://x.com/josephdelong/status/1735293295301972022?s=20) [4](https://twitter.com/Mudit__Gupta/status/1735301007188406681) [5](https://twitter.com/FrankResearcher/status/1735286837088792794) [6](https://twitter.com/Ledger/status/1735326240658100414) [7](https://twitter.com/AndrewMohawk/status/1735290127084105743) [8](https://twitter.com/bantg/status/1735279127752540465) 
| 2023 Sep 27   | Spoofed Dependabot commits steal GitHub tokens and inject malware to JavaScript files | [Checkmarx](https://checkmarx.com/blog/surprise-when-dependabot-contributes-malicious-code/)
| 2023 Jun 27   | Manifest Confusion - a new publicly disclosed bug with the npm package manager demonstrating package metadata inconsistency | [Darcy Clarke's blog](https://blog.vlt.sh/blog/the-massive-hole-in-the-npm-ecosystem)
| 2023 Jun 23   | North Korean attackers exploit social engineering and supply chain attacks on npm | [Phylum](https://blog.phylum.io/junes-sophisticated-npm-attack-attributed-to-north-korea/)
| 2023 Jun 15   | Supply Chain Attack Exploits Abandoned S3 Buckets to Distribute Malicious Binaries for [bignum npm package](https://www.npmjs.com/package/bignum?activeTab=versions) | [The Hacker News](https://thehackernews.com/2023/06/new-supply-chain-attack-exploits.html), [Checkmarx](https://checkmarx.com/blog/hijacking-s3-buckets-new-attack-technique-exploited-in-the-wild-by-supply-chain-attackers/)
| 2023 Jun 06   | Recommended packages by ChatGPT may be exploited for supply chain security attack vector| [Vulcan](https://vulcan.io/blog/ai-hallucinations-package-risk)
| 2023 Feb 16   | Researchers Hijack Popular NPM Package with Millions of Downloads | [Illustria on The Hacker News](https://thehackernews.com/2023/02/researchers-hijack-popular-npm-package.html)
| 2023 Feb 10   | Researchers Uncover Obfuscated Malicious Code in PyPI Python Packages, affiliated npm ecosystem evidence too | [The Hacker News](https://thehackernews.com/2023/02/researchers-uncover-obfuscated.html)
| 2023 Jan 29   | Phylum Identifies 137 Malicious npm Packages | [phylum](https://blog.phylum.io/phylum-identifies-98-malicious-npm-packages)
| 2022 Nov 29   | Invisible npm malware may hide in crafted versions and bypass npm audit's security checks | [JFrog](https://jfrog.com/blog/invisible-npm-malware-evading-security-checks-with-crafted-versions/)
| 2022 Nov 24   | Phylum team captures captures malicious npm package imagecompress-mini claims to be an image compress tool | [Louisw Lang on Twitter](https://twitter.com/LouiswLang/status/1595835195382534144)
| 2022 Oct 12   | Aqua security discovers flaw in npm that allows disclosing of privately hosted npm packages on the registry | [Aqua](https://blog.aquasec.com/private-packages-disclosed-via-timing-attack-on-npm) 
| 2022 Oct 07   | LofyGang Distributed ~200 Malicious NPM Packages to Steal Credit Card Data | [TheHackerNews](https://thehackernews.com/2022/10/lofygang-distributed-200-malicious-npm.html)
| 2022 Sep 23    |  Popular Cryptocurrency Exchange dYdX Has Had Its NPM Account Hacked | [Mend](https://www.mend.io/resources/blog/popular-cryptocurrency-exchange-dydx-has-had-its-npm-account-hacked/)
| 2022 Jul 29    | malicious packages `small-sm`, `pern-valids`, `lifeculer`, and `proc-title` target stealing credit card information and discord tokens | [darkreading](https://www.darkreading.com/risk/malicious-npm-packages-discord-tokens-credit-card)
| 2022 May 26    | stolen oAuth GitHub tokens lead to npm security breach, compromised user accounts metadata, private packages, and plain-text passwords in logs | [GitHub](https://github.blog/2022-05-26-npm-security-update-oauth-tokens/)
| 2022 May 24    | malicious npm packages exploiting dependency confusion attacks | [Snyk](https://snyk.io/blog/snyk-200-malicious-npm-packages-cobalt-strike-dependency-confusion-attacks/), [Snyk](https://snyk.io/blog/npm-dependency-confusion-attack-gxm-reference/)
| 2022 May 23    | npm packages hijacked due to expired domains | [TheRegister](https://www.theregister.com/2022/05/23/npm_dependencies_vulnerable/)
| 2022 Apr 05  | New npm Flaws Let Attackers Better Target Packages for Account Takeover | [Aqua](https://blog.aquasec.com/npm-supply-chain-attack)
| 2022 Apr 26  | npm package planting | [Aqua](https://blog.aquasec.com/npm-package-planting), [The Hacker News](https://thehackernews.com/2022/04/npm-bug-allowed-attackers-to-distribute.html)
| 2022 Mar 31  | More protestware from `styled-components` | [Checkmarx Security blog](https://checkmarx.com/blog/new-protestware-found-lurking-in-highly-popular-npm-package/)
| 2022 Mar 18  | More protestware from `es5-ext` and `event-source-pollyfill`  | [Snyk advisory for event-source-pollyfill](https://security.snyk.io/vuln/SNYK-JS-EVENTSOURCEPOLYFILL-2429580), [es5-ext commit](https://github.com/medikoo/es5-ext/commit/28de285ed433b45113f01e4ce7c74e9a356b2af2), [ArsTechnica](https://arstechnica.com/information-technology/2022/03/sabotage-code-added-to-popular-npm-package-wiped-files-in-russia-and-belarus/) |
| 2022 March 16  | `peacenotwar` module sabotages npm developers in the `node-ipc` package to protest the invasion of Ukraine | [Snyk blog](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability), [Darkreading](https://www.darkreading.com/application-security/recent-code-sabotage-incident-latest-to-highlight-code-dependency-risks), [SC Magazine](https://www.scmagazine.com/analysis/application-security/what-happens-when-protestware-sabotages-open-source-in-response-to-current-events) |
| 2022 Mar 7  | Malicious packages caught exfiltrating data via legit webhook services | [Checkmarx Security blog](https://medium.com/checkmarx-security/webhook-party-malicious-packages-caught-exfiltrating-data-via-legit-webhook-services-6e046b07d191) |
| 2022 Feb 22  | 25 Malicious JavaScript Libraries due to typosquatting attacks | [TheHackerNews](https://thehackernews.com/2022/02/25-malicious-javascript-libraries.html) |
| 2022 Feb 11  | 2,818 npm accounts use email addresses with expired domains | [TheRecord](https://therecord.media/thousands-of-npm-accounts-use-email-addresses-with-expired-domains) |
| 2021 Dec 08  | 17 JavaScript libraries contained malicious code to collect and steal Discord access tokens and environment variables from users’ computers -                   | [TheRecord](https://therecord.media/malicious-npm-packages-caught-stealing-discord-tokens-environment-variables/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 2021 December 01  | The Bladabindi trojan and RAT malware | [Sonatype](https://blog.sonatype.com/bladabindi-njrat-rat-in-jdb.js-npm-malware) |
| 2021 November 04  | coa and rc packages - Popular npm library 'coa' was hijacked today with malicious code injected into it, ephemerally impacting React pipelines around the world | [Bleepingcomputer](https://www.bleepingcomputer.com/news/security/popular-coa-npm-library-hijacked-to-steal-user-passwords), [the record](https://therecord.media/malware-found-in-coa-and-rc-two-npm-packages-with-23m-weekly-downloads/), [npm tweet](https://twitter.com/npmjs/status/1456310627362742284), [npm tweet for rc](https://twitter.com/npmjs/status/1456398505832976384).                                                                                                                                                                                                                                                                                      |
| 2021 October 27   | noblox.js-proxy and noblox.js - typosquatted npm package that target users of official roblox API and SDK npm package (noblox.js)                               | [the register](https://www.theregister.com/2021/10/27/npm_roblox_ransomware)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 2021 October 22   | ua-parser-js - Versions of a popular NPM package named ua-parser-js was found to contain malicious code                                                         | [Cybersecurity and Infrastructure Security Agency (CISA)](https://us-cert.cisa.gov/ncas/current-activity/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js), [github issue](https://github.com/faisalman/ua-parser-js/issues/536), [IOCs](https://twitter.com/BleepinComputer/status/1451964720974635021?s=20), [portswigger](https://portswigger.net/daily-swig/popular-npm-package-ua-parser-js-poisoned-with-cryptomining-password-stealing-malware), [theregister](https://www.theregister.com/2021/10/27/npm_roblox_ransomware)                                                                                                                             |
| 2021 September 02 | pac-resolver - can enable threat actors on the local network to run arbitrary code within your Node.js process whenever it attempts to make an HTTP request     | [arstechnica.com](https://arstechnica.com/information-technology/2021/09/npm-package-with-3-million-weekly-downloads-had-a-severe-vulnerability/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 2021 August 07    | npm package ownership process firing back and exposing potential vectors for supply chain security risks.                                                       | [Twitter](https://twitter.com/Andrewmd5/status/1423915732979437571)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 2021 April 13  |  New Linux, macOS malware hidden in fake Browserify NPM package: web-browserify | [Bleepingcomputer](https://www.bleepingcomputer.com/news/security/new-linux-macos-malware-hidden-in-fake-browserify-npm-package).                                                                                                                                                                 |
| 2020 December 02  | **jdb.js - db-json.js** - malicious npm packages caught installing remote access trojans.                                                                       | [zdnet.com](https://www.zdnet.com/google-amp/article/malicious-npm-packages-caught-installing-remote-access-trojans/), [Bleepingcomputer](https://www.bleepingcomputer.com/news/microsoft/malicious-npm-packages-used-to-install-njrat-remote-access-trojan/).                                                                                                                                                                                                                                                                                                                                                                                                                |
| 2020 November 09  | **discord malicious npm package** - Npm package caught stealing sensitive Discord and browser files                                                             | [sonatype](https://blog.sonatype.com/discord.dll-successor-to-npm-fallguys-),  [zdnet](https://www.zdnet.com/article/npm-package-caught-stealing-sensitive-discord-and-browser-files/).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 2020 November 03  | **twilio-npm** - malicious npm package opens backdoors on programmers' computers.                                                                               | [zdnet](https://www.zdnet.com/article/malicious-npm-package-opens-backdoors-on-programmers-computers)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| 2020 August 29    | **fallguys** - malicious package stealing sensitive files.                                                                                                      | [zdnet](https://www.zdnet.com/article/malicious-npm-package-caught-trying-to-steal-sensitive-discord-and-browser-files/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 2020 April 27     | **is-promise** - one-liner library breaks an ecosystem.                                                                                                         | [Forbes Lindesay - Maintainer post-mortem](https://medium.com/javascript-in-plain-english/is-promise-post-mortem-cab807f18dcc), [snyk's postmortem](https://snyk.io/blog/why-did-is-promise-happen-and-what-can-we-learn-from-it/)                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 2019 August 22    | **bb-builder** - malicious package targeting Windows systems to exfiltrate information and send to a remote service.                                            | [Snyk](https://snyk.io/vuln/SNYK-JS-BBBUILDER-460132), [Reversing Labs](https://blog.reversinglabs.com/blog/the-npm-package-that-walked-away-with-all-your-passwords), [Bleeping Computer](https://www.technadu.com/malicious-package-stealing-user-credentials-npm-repository/77482/)                                                                                                                                                                                                                                                                                                                                                                                        |
| 2019 June 05      | **EasyDEX-GUI** - malicious code found in npm package event-stream.                                                                                             | [npm](https://blog.npmjs.org/post/185397814280/plot-to-steal-cryptocurrency-foiled-by-the-npm), [snyk](https://snyk.io/blog/yet-another-malicious-package-found-in-npm-targeting-cryptocurrency-wallets), [komodo announcement](https://komodoplatform.com/update-agama-vulnerability/)                                                                                                                                                                                                                                                                                                                                                                                       |
| 2018 November 27  | **event-stream** - malicious code found in npm package event-stream.                                                                                            | [github issue](https://github.com/dominictarr/event-stream/issues/116) [snyk](https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream), [snyk's postmortem](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor),  [schneid](https://schneid.io/blog/event-stream-vulnerability-explained/), [intrinsic](https://medium.com/intrinsic/compromised-npm-package-event-stream-d47d08605502), [npm](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident), [jayden](https://jaydenseric.com/blog/event-stream-compromise), [hillel wayne's postmortem](https://www.hillelwayne.com/post/stamping-on-eventstream/) |
| 2018 July 12      | **eslint** - malicious packages found in npm package eslint-scope and eslint-config-eslint.                                                                     | [github issue](https://github.com/eslint/eslint-scope/issues/39), [eslint tweet](https://twitter.com/geteslint/status/1017419074136092673?lang=en), [eslint's postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes), [nodesource's postmortem](https://nodesource.com/blog/a-high-level-post-mortem-of-the-eslint-scope-security-incident/), [npm's statement](https://status.npmjs.org/incidents/dn7c1fgrr7ng)                                                                                                                                                                                                                             |
| 2018 May 02       | **getcookies** - malicious package getcookies gets embedded in higher-level express related packages.                                                           | [GitHub issue](https://github.com/RocketChat/Rocket.Chat/issues/10641), [npm](https://blog.npmjs.org/post/173526807575/reported-malicious-module-getcookies), [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/somebody-tried-to-hide-a-backdoor-in-a-popular-javascript-npm-package/), [Snyk’s getcookies vulnerability page](https://snyk.io/vuln/npm:getcookies:20180502), [Hacker News](https://news.ycombinator.com/item?id=16975025)                                                                                                                                                                                                               |
| 2018 Feb 13    | maintainer account with access to conventional-changelog npm package compromised and published malware for 1 day and 11 hours | [conventional-changelog repository update](https://github.com/conventional-changelog/conventional-changelog/issues/282#issuecomment-365367804)
| 2017 August 02    | **crossenv** - malicious typosquatting package crossenv steals environment variables.                                                                           | [CJ blog on typosquat packages](https://medium.com/@ceejbot/crossenv-malware-on-the-npm-registry-45c7dc29f6f5), [Typosquatting research paper](https://incolumitas.com/2016/06/08/typosquatting-package-managers/), [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/javascript-packages-caught-stealing-environment-variables/), [Snyk’s crossenv vulnerability page](https://snyk.io/vuln/npm:crossenv:20170802), [Hacker News](https://news.ycombinator.com/item?id=14901566)                                                                                                                                                                         |
| 2016 March 22     | **left-pad** - how one developer broke Node, Babel and thousands of projects in 11 lines of JavaScript.                                                         | [left-pad.io](http://left-pad.io), [The Register](https://www.theregister.co.uk/2016/03/23/npm_left_pad_chaos), [qurtaz](https://qz.com/646467/how-one-programmer-broke-the-internet-by-deleting-a-tiny-piece-of-code).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |




Follow-up notes:
* A resource for malicious incidents is [BadJS](https://badjs.org/) - a repository of malicious JavaScript that has been found in websites, extensions, npm packages, and anywhere else JavaScript lives.
* [npm zoo](https://github.com/spaceraccoon/npm-zoo) is an archive keeping track of the original malicious packages source code for educational purposes.

# Educational

## Newsletters
 - [Node.js Security newsletter](https://newsletter.nodejs-security.com/) - JavaScript & web security insights, latest security vulnerabilities, hands-on secure code insights, npm ecosystem incidents, Node.js runtime feature updates, Bun and Deno runtime updates, secure coding best practices, malware, malicious packages, and more.

## Articles
 - [A Roadmap for Node.js Security](https://node-sec-roadmap-fyi.uc.r.appspot.com/) (original domain https://nodesecroadmap.fyi/ not available. See [#42](https://github.com/lirantal/awesome-nodejs-security/issues/42))
 - [10 npm security best practices](https://snyk.io/blog/ten-npm-security-best-practices/)
 - [OWASP Cheat Sheet Series - Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_security_cheat_sheet.html)
 - [What is a backdoor? Let’s build one with Node.js](https://snyk.io/blog/what-is-a-backdoor/)
 - [The Anatomy of a Malicious Package](https://blog.phylum.io/malicious-javascript-code-in-npm-malware/)
 - [Why npm lockfiles can be a security blindspot for injecting malicious modules](https://snyk.io/blog/why-npm-lockfiles-can-be-a-security-blindspot-for-injecting-malicious-modules/)
 - [GitHub Actions to securely publish npm packages](https://snyk.io/blog/github-actions-to-securely-publish-npm-packages/)
 - [Top 11 Node.js security best practices | Sqreen.com](https://blog.sqreen.com/nodejs-security-best-practices/)
 - [A Tale of (prototype) Poisoning](https://www.fastify.io/docs/latest/Guides/Prototype-Poisoning/)
 - [Securizing your GitHub org](https://dev.to/nodesecure/securize-your-github-org-4lb7)
 - [Research Case Study: Supply Chain Security at Scale – Insights into NPM Account Takeovers](https://laburity.com/research-npm-account-takeovers/)
 - [npm Security Best Practices](https://github.com/lirantal/npm-security-best-practices)

## Research Papers
 - [Deep dive into Visual Studio Code extension security vulnerabilities](https://snyk.io/blog/visual-studio-code-extension-security-vulnerabilities-deep-dive)

## Books
- [Secure Your Node.js Web Application: Keep Attackers Out and Users Happy](https://www.amazon.com/Secure-Your-Node-js-Web-Application-ebook/dp/B01BPPUP30) by Karl Duuna, 2016
- [Essential Node.js Security](https://leanpub.com/nodejssecurity) by Liran Tal, 2017 - Hands-on and abundant with source code for a practical guide to Securing Node.js web applications.
- [Securing Node JS Apps
](https://leanpub.com/securingnodeapps) by Ben Edmunds, 2016 - Learn the security basics that a senior developer usually acquires over years of experience, all condensed down into one quick and easy handbook.
- [Web Developer Security Toolbox
](https://leanpub.com/b/webdevelopersecuritytoolbox) - Bundled Node.js and Web Security Books.
- [Thomas Gentilhomme](https://github.com/fraxken) book: [Become a Node.js Developer](https://github.com/fraxken/ebook_nodejs)
- [Node.js Secure Coding: Defending Against Command Injection Vulnerabilities](https://www.nodejs-security.com/book/command-injection/)
- [Node.js Secure Coding: Prevention and Exploitation of Path Traversal Vulnerabilities](https://www.nodejs-security.com/book/path-traversal)
- [Node.js Secure Coding: Mitigate and Weaponize Code Injection Vulnerabilities](https://www.nodejs-security.com/book/code-injection)

## Roadmaps
  - [Node.js Developer Roadmap](https://roadmap.sh/nodejs)

# Companies
- [Snyk](https://snyk.io) - A developer-first solution that automates finding & fixing vulnerabilities in your dependencies.
- [Sqreen](https://sqreen.io) - Automated security for your web apps - real time application security protection.
- [NodeSource](https://nodesource.com) - Mission-critical Node.js applications. Provides N|Solid and Node Certified Modules.
- [GuardRails](https://www.guardrails.io) - A GitHub App that gives you instant security feedback in your Pull Requests.
- [NodeSecure](https://github.com/NodeSecure) - An organization of developers building free and open source JavaScript/Node.js security tools.

## Hacking Playground
 - [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) - The OWASP NodeGoat project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
 - [OWASP Juice Shop](https://github.com/bkimminich/juice-shop) - The OWASP Juice Shop is an intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.
 - [DomGoat](https://domgo.at/cxss/intro) - Client XSS happens when untrusted data from sources ends up in sinks. Information and excercises on different sources, different sinks and example of XSS occuring due to them in the menu on the left-hand side. 

# Contributing
Found an awesome project, package, article, other type of resources related to Node.js Security? Send me a pull request!
Just follow the [guidelines](/CONTRIBUTING.md). Thank you!

---
say *hi* on [Twitter](https://twitter.com/liran_tal)

## License
[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

<br/>
<div align="center">

A curated list of awesome Node.js Security resources.

![#](https://badgen.net/badge/tools/30+/blue)
![#](https://badgen.net/badge/incidents/15+/red)
![#](https://badgen.net/badge/educational/8+/green)

[![liran_tal](https://img.shields.io/twitter/url/https/twitter.com/liran_tal.svg?style=social&label=Follow%20%40Liran%20Tal)](https://twitter.com/liran_tal)

 *List inspired by the [awesome](https://github.com/sindresorhus/awesome) list thing.*

</div>
<br/>

# Contents

- [Tools](#projects)
  - [Web Framework Hardening](#web-framework-hardening)
  - [Static Code Analysis](#static-code-analysis)
  - [Dynamic Application Security Testing](#dynamic-application-security-testing)
  - [Input/Output Validation](#input-validation--output-encoding)
  - [Secure Composition](#secure-composition)
  - [CSRF](#csrf)
  - [Vulnerabilities and Security Advisories](#vulnerabilities-and-security-advisories)
  - [Security Hardening](#security-hardening)
- [Security Incidents](#security-incidents)
- [Educational](#educational)
  - [Hacking Playground](#hacking-playground)
  - [Articles](#articles)
  - [Research Papers](#research-papers)
  - [Books](#books)
- [Companies](#companies)

# Tools

## Web Framework Hardening
- [Helmet](https://www.npmjs.com/package/helmet) - Helmet helps you secure your Express apps by setting various HTTP headers.
- [koa-helmet](https://www.npmjs.com/package/koa-helmet) - koa-helmet helps you secure your Koa apps by setting various HTTP headers.
- [blankie](https://github.com/nlf/blankie) - CSP plugin for [hapi](https://github.com/hapijs/hapi).
- [fastify-helmet](https://github.com/fastify/fastify-helmet) - fastify-helmet helps you secure your [fastify](https://www.fastify.io/) apps by setting important secutiry headers.

## Static Code Analysis
- [eslint-plugin-security](https://www.npmjs.com/package/eslint-plugin-security) - ESLint rules for Node Security. This project will help identify potential security hotspots, but finds a lot of false positives which need triage by a human.
- [tslint-plugin-security](https://www.npmjs.com/package/tslint-config-security) - TSLint rules for Node Security. This project will help identify potential security hotspots, but finds a lot of false positives which need triage by a human.
- [safe-regex](https://www.npmjs.com/package/safe-regex) - detect potentially catastrophic exponential-time regular expressions by limiting the star height to 1.
- [vuln-regex-detector](https://www.npmjs.com/package/vuln-regex-detector) - This module lets you check a regex for vulnerability. In JavaScript, regular expressions (regexes) can be "vulnerable": susceptible to catastrophic backtracking. If your application is used on the client side, this can be a performance issue. On the server side, this can expose you to Regular Expression Denial of Service (REDOS).
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevents you from committing secrets and credentials into git repositories.
- [DevSkim](https://github.com/Microsoft/DevSkim) - DevSkim is a set of IDE plugins and rules that provide security "linting" capabilities. Also has support for CLI so it can be integrated into CI/CD pipeline.
- [ban-sensitive-files](https://github.com/bahmutov/ban-sensitive-files) - Checks filenames to be committed against a library of filename rules to prevent storing sensitive files in Git. Checks some files for sensitive contents (for example authToken inside .npmrc file).
- [NodeJSScan](https://github.com/ajinabraham/nodejsscan) - A static security code scanner for Node.js applications. Including neat UI that can point where the issue is and how to fix it.
- [Nsecure](https://github.com/ES-Community/nsecure) - Node.js CLI that allow you to deeply analyze the dependency tree of a given npm package or a directory.
- [Trust But Verify](https://github.com/verifynpm/tbv) - TBV compares an npm package with its source repository to ensure the resulting artifact is the same.
- [lockfile-lint](https://github.com/lirantal/lockfile-lint) - lint lockfiles for improved security and trust policies to keep clean from malicious package injection and other insecure configurations.
- [pkgsign](https://github.com/RedpointGames/pkgsign) - A CLI tool for signing and verifying npm and yarn packages.
- [semgrep](https://semgrep.dev) - Open-source, offline, easy-to-customize static analysis for many languages. Some others on this list (NodeJSScan) use semgrep as their engine.
- [npm-scan](https://github.com/spaceraccoon/npm-scan) - An extensible, heuristic-based vulnerability scanning tool for installed npm packages.
- [js-x-ray](https://github.com/fraxken/js-x-ray) - JavaScript and Node.js SAST scanner capable of detecting various well-known malicious code patterns (Unsafe import, Unsafe stmt, Unsafe RegEx, encoded literals, minified and obfuscated codes).
- [cspscanner](https://cspscanner.com/) - CSP Scanner helps developers and security experts to easily inspect and evaluate a site’s Content Security (CSP).
- [eslint-plugin-anti-trojan-source](https://github.com/lirantal/eslint-plugin-anti-trojan-source) - ESLint plugin to detect and prevent Trojan Source attacks from entering your codebase.

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

## Security Hardening
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
- [allowed-scripts](https://github.com/dominykas/allow-scripts) Execute allowed `npm install` lifecycle scripts.

# Security Incidents

Collection of security incidents that happened in the Node.js, JavaScript and npm related communities with supporting articles:

| Date              | Name                                                                                                                                                            | Reference Links                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2022 February 22  | 25 Malicious JavaScript Libraries due to typosquatting attacks | [TheHackerNews](https://thehackernews.com/2022/02/25-malicious-javascript-libraries.html) |
| 2022 February 11  | 2,818 npm accounts use email addresses with expired domains | [TheRecord](https://therecord.media/thousands-of-npm-accounts-use-email-addresses-with-expired-domains) |
| 2021 December 08  | 17 JavaScript libraries contained malicious code to collect and steal Discord access tokens and environment variables from users’ computers -                   | [TheRecord](https://therecord.media/malicious-npm-packages-caught-stealing-discord-tokens-environment-variables/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
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
| 2017 August 02    | **crossenv** - malicious typosquatting package crossenv steals environment variables.                                                                           | [CJ blog on typosquat packages](https://medium.com/@ceejbot/crossenv-malware-on-the-npm-registry-45c7dc29f6f5), [Typosquatting research paper](https://incolumitas.com/2016/06/08/typosquatting-package-managers/), [bleepingcomputer.com](https://www.bleepingcomputer.com/news/security/javascript-packages-caught-stealing-environment-variables/), [Snyk’s crossenv vulnerability page](https://snyk.io/vuln/npm:crossenv:20170802), [Hacker News](https://news.ycombinator.com/item?id=14901566)                                                                                                                                                                         |
| 2016 March 22     | **left-pad** - how one developer broke Node, Babel and thousands of projects in 11 lines of JavaScript.                                                         | [left-pad.io](http://left-pad.io), [The Register](https://www.theregister.co.uk/2016/03/23/npm_left_pad_chaos), [qurtaz](https://qz.com/646467/how-one-programmer-broke-the-internet-by-deleting-a-tiny-piece-of-code).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |




Follow-up notes:
* A resource for malicious incidents is [BadJS](https://badjs.org/) - a repository of malicious JavaScript that has been found in websites, extensions, npm packages, and anywhere else JavaScript lives.
* [npm zoo](https://github.com/spaceraccoon/npm-zoo) is an archive keeping track of the original malicious packages source code for educational purposes.

# Educational

## Hacking Playground
 - [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) - The OWASP NodeGoat project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
 - [OWASP Juice Shop](https://github.com/bkimminich/juice-shop) - The OWASP Juice Shop is an intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.
 - [DomGoat](https://domgo.at/cxss/intro) - Client XSS happens when untrusted data from sources ends up in sinks. Information and excercises on different sources, different sinks and example of XSS occuring due to them in the menu on the left-hand side. 

## Articles
 - [A Roadmap for Node.js Security](https://nodesecroadmap.fyi/)
 - [10 npm security best practices](https://snyk.io/blog/ten-npm-security-best-practices/)
 - [OWASP Cheat Sheet Series - Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_security_cheat_sheet.html)
 - [What is a backdoor? Let’s build one with Node.js](https://snyk.io/blog/what-is-a-backdoor/)
 - [The Anatomy of a Malicious Package](https://blog.phylum.io/malicious-javascript-code-in-npm-malware/)
 - [Why npm lockfiles can be a security blindspot for injecting malicious modules](https://snyk.io/blog/why-npm-lockfiles-can-be-a-security-blindspot-for-injecting-malicious-modules/)
 - [GitHub Actions to securely publish npm packages](https://snyk.io/blog/github-actions-to-securely-publish-npm-packages/)
 - [Top 11 Node.js security best practices | Sqreen.com](https://blog.sqreen.com/nodejs-security-best-practices/)

## Research Papers
 - [Deep dive into Visual Studio Code extension security vulnerabilities](https://snyk.io/blog/visual-studio-code-extension-security-vulnerabilities-deep-dive)

## Books
- [Secure Your Node.js Web Application: Keep Attackers Out and Users Happy](https://www.amazon.com/Secure-Your-Node-js-Web-Application-ebook/dp/B01BPPUP30) by Karl Duuna, 2016
- [Essential Node.js Security](https://leanpub.com/nodejssecurity) by Liran Tal, 2017 - Hands-on and abundant with source code for a practical guide to Securing Node.js web applications.
- [Securing Node JS Apps
](https://leanpub.com/securingnodeapps) by Ben Edmunds, 2016 - Learn the security basics that a senior developer usually acquires over years of experience, all condensed down into one quick and easy handbook.
- [Web Developer Security Toolbox
](https://leanpub.com/b/webdevelopersecuritytoolbox) - Bundled Node.js and Web Security Books.

# Companies
- [Snyk](https://snyk.io) - A developer-first solution that automates finding & fixing vulnerabilities in your dependencies.
- [Sqreen](https://sqreen.io) - Automated security for your web apps - real time application security protection.
- ~~[Intrinsic](https://intrinsic.com) - Intrinsic secures your sensitive data from bugs and malicious code, allowing you to run all code safely.~~
- [NodeSource](https://nodesource.com) - Mission-critical Node.js applications. Provides N|Solid and Node Certified Modules.
- [GuardRails](https://www.guardrails.io) - A GitHub App that gives you instant security feedback in your Pull Requests.
- [NodeSecure](https://github.com/NodeSecure) - An organization of developers building free and open source JavaScript/Node.js security tools.

# Contributing
Found an awesome project, package, article, other type of resources related to Node.js Security? Send me a pull request!
Just follow the [guidelines](/CONTRIBUTING.md). Thank you!

---
say *hi* on [Twitter](https://twitter.com/liran_tal)

## License
[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0/)

<br/>
<div align="center">

A curated list of awesome Node.js Security related resources.

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

 *List inspired by the [awesome](https://github.com/sindresorhus/awesome) list thing.*

</div>
<br/>

# Contents

- [Tools](#projects)
  - [Web Framework Hardening](#web-framework-hardening)
  - [Static Code Analysis](#static-code-analysis)
  - [Input/Output Validation](#input-output-validation)
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
- [blankie](https://github.com/nlf/blankie) - CSP plugin for [hapi](https://github.com/hapijs/hapi).

## Static Code Analysis
- [eslint-plugin-security](https://www.npmjs.com/package/eslint-plugin-security) - ESLint rules for Node Security. This project will help identify potential security hotspots, but finds a lot of false positives which need triage by a human.
- [safe-regex](https://www.npmjs.com/package/safe-regex) - detect potentially catastrophic exponential-time regular expressions by limiting the star height to 1.
- [vuln-regex-detector](https://www.npmjs.com/package/vuln-regex-detector) - This module lets you check a regex for vulnerability. In JavaScript, regular expressions (regexes) can be "vulnerable": susceptible to catastrophic backtracking. If your application is used on the client side, this can be a performance issue. On the server side, this can expose you to Regular Expression Denial of Service (REDOS).
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevents you from committing secrets and credentials into git repositories.
- [DevSkim](https://github.com/Microsoft/DevSkim) - DevSkim is a set of IDE plugins and rules that provide security "linting" capabilities. Also has support for CLI so it can be integrated into CI/CD pipeline.
- [ban-sensitive-files](https://github.com/bahmutov/ban-sensitive-files) - Checks filenames to be committed against a library of filename rules to prevent storing sensitive files in Git. Checks some files for sensitive contents (for example authToken inside .npmrc file).
- [NodeJSScan](https://ajinabraham.github.io/NodeJsScan/) - A static security code scanner for Node.js applications. Including neat UI that can point where the issue is and how to fix it.

## Input Validation & Output Encoding
- [node-esapi](https://www.npmjs.com/package/node-esapi) - node-esapi is a minimal port of the ESAPI4JS (Enterprise Security API for JavaScript) encoder.
- [escape-html](https://www.npmjs.com/package/escape-html) - Escape string for use in HTML.
- [js-string-escape](https://www.npmjs.com/package/js-string-escape) - Escape any string to be a valid JavaScript string literal between double quotes or single quotes.
- [validator](https://github.com/chriso/validator.js) - An npm library of string validators and sanitizers.
- [xss-filters](https://www.npmjs.com/package/xss-filters) - Just sufficient output filtering to prevent XSS!

## CSRF
- [csurf](https://www.npmjs.com/package/csurf) - Node.js CSRF protection middleware.
- [crumb](https://github.com/hapijs/crumb) - CSRF crumb generation and validation for [hapi](https://github.com/hapijs/hapi).

## Vulnerabilities and Security Advisories
- [npq](https://github.com/lirantal/npq) - Safely install packages with npm or yarn by auditing them as part of your install process.
- [snyk](https://www.npmjs.com/package/snyk) - Snyk helps you find, fix and monitor known vulnerabilities in Node.js npm, Ruby and Java dependencies, both on an ad hoc basis and as part of your CI (Build) system.
- [node-release-lines](https://www.npmjs.com/package/node-release-lines) - Introspection API for Node.js release metadata. Provides information about release lines, their relative status along with details of each release.
- [auditjs](https://github.com/OSSIndex/auditjs) - Audits an NPM package.json file to identify known vulnerabilities using the [OSSIndex](https://ossindex.sonatype.org/rest).
- [npm-audit](https://docs.npmjs.com/cli/audit) - Runs a security audit based on your package.json using npm.
- [npm-audit-resolver](https://www.npmjs.com/package/npm-audit-resolver) - Manage npm-audit results, including options to ignore specific issues in clear and auditable way.
- [gammaray](https://github.com/nearform/gammaray) - Runs a security audit based on your package.json using the [Node.js Security Working Group vulnerability data](https://github.com/nodejs/security-wg/).

## Security Hardening
- [express-limiter](https://www.npmjs.com/package/express-limiter) - Rate limiting middleware for Express applications built on redis.
- [limits](https://www.npmjs.com/package/limits) - Simple express/connect middleware to set limit to upload size, set request timeout etc.
- [rate-limiter-flexible](https://www.npmjs.com/package/rate-limiter-flexible) - Fast, flexible and friendly rate limiter by key and protection from DDoS and brute force attacks in process Memory, Cluster, Redis, MongoDb, MySQL, PostgreSQL at any scale. Express and Koa examples included.


# Security Incidents

Collection of security incidents that happened in the Node.js, JavaScript and npm related communities with supporting articles:

* **event-stream** - malicious code found in npm package event-stream. References: [[github issue]](https://github.com/dominictarr/event-stream/issues/116) [[snyk]](https://snyk.io/blog/malicious-code-found-in-npm-package-event-stream), [[snyk's postmortem]](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor),  [[schneid]](https://schneid.io/blog/event-stream-vulnerability-explained/), [[intrinsic]](https://medium.com/intrinsic/compromised-npm-package-event-stream-d47d08605502), [[npm]](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident), [[jayden]](https://jaydenseric.com/blog/event-stream-compromise), [[hillel wayne's postmortem]](https://www.hillelwayne.com/post/stamping-on-eventstream/)
* **eslint** - malicious packages found in npm package eslint-scope and eslint-config-eslint. References [[github issue]](https://github.com/eslint/eslint-scope/issues/39), [[eslint tweet]](https://twitter.com/geteslint/status/1017419074136092673?lang=en), [[eslint's postmortem]](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes), [[nodesource's postmortem]](https://nodesource.com/blog/a-high-level-post-mortem-of-the-eslint-scope-security-incident/), [[npm's statement]](https://status.npmjs.org/incidents/dn7c1fgrr7ng)
* **getcookies** - malicious package getcookies gets embedded in higher-level express related packages. References: [[GitHub issue]](https://github.com/RocketChat/Rocket.Chat/issues/10641)
[[npm]](https://blog.npmjs.org/post/173526807575/reported-malicious-module-getcookies)
[[bleepingcomputer.com]](https://www.bleepingcomputer.com/news/security/somebody-tried-to-hide-a-backdoor-in-a-popular-javascript-npm-package/)
[[Snyk’s getcookies vulnerability page]](https://snyk.io/vuln/npm:getcookies:20180502)
[[Hacker News]](https://news.ycombinator.com/item?id=16975025)


# Educational

## Hacking Playground
 - [NodeGoat](https://github.com/OWASP/NodeGoat) - The OWASP NodeGoat project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
 - [OWASP Juice Shop is an intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.](https://github.com/bkimminich/juice-shop) - 

## Articles
 - [A Roadmap for Node.js Security](https://nodesecroadmap.fyi/)

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
- [Intrinsic](https://intrinsic.com) - Intrinsic secures your sensitive data from bugs and malicious code, allowing you to run all code safely.
- [NodeSource](https://nodesource.com) - Mission-critical Node.js applications. Provides N|Solid and Node Certified Modules.
- [GuardRails](https://www.guardrails.io) - A GitHub App that gives you instant security feedback in your Pull Requests.


# Contributing
Found an awesome project, package, article, other type of resources related to Node.js Security? Send me a pull request!
Just follow the [guidelines](/CONTRIBUTING.md). Thank you!

---
say *hi* on [Twitter](https://twitter.com/liran_tal)


## License
[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0/)


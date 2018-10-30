<br/>
<div align="center">

A curated list of awesome Node.js Security related resources.

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

 *List inspired by the [awesome](https://github.com/sindresorhus/awesome) list thing.*

</div>
<br/>

# Table of Contents

- [Tools](#projects)
  - [Web Framework Hardening](#web-framework-hardening)
  - [Static Code Analysis](#static-code-analysis)
  - [Input/Output Validation](#input-output-validation)
  - [CSRF](#csrf)
  - [Vulnerabilities and Security Advisories](#vulnerabilities-and-security-advisories)
  - [Security Hardening](#security-hardening)
- [Educational](#educational)
  - [Hacking Playground](#hacking-playground)
  - [Articles](#articles)
  - [Research Papers](#research-papers)
  - [Books](#books)
- [Companies](#companies)

# Tools

## Web Framework Hardening
- [Helmet](https://www.npmjs.com/package/helmet) - Helmet helps you secure your Express apps by setting various HTTP headers.

## Static Code Analysis
- [eslint-plugin-security](https://www.npmjs.com/package/eslint-plugin-security) - ESLint rules for Node Security. This project will help identify potential security hotspots, but finds a lot of false positives which need triage by a human.
- [safe-regex](https://www.npmjs.com/package/safe-regex) - detect potentially catastrophic exponential-time regular expressions by limiting the star height to 1.
- [vuln-regex-detector](https://www.npmjs.com/package/vuln-regex-detector) - This module lets you check a regex for vulnerability. In JavaScript, regular expressions (regexes) can be "vulnerable": susceptible to catastrophic backtracking. If your application is used on the client side, this can be a performance issue. On the server side, this can expose you to Regular Expression Denial of Service (REDOS).
- [git-secrets](https://github.com/awslabs/git-secrets) - Prevents you from committing secrets and credentials into git repositories.
- [DevSkim](https://github.com/Microsoft/DevSkim) - DevSkim is a set of IDE plugins and rules that provide security "linting" capabilities. Also has support for CLI so it can be integrated into CI/CD pipeline.

## Input/Output Validation
- [node-esapi](https://www.npmjs.com/package/node-esapi) - node-esapi is a minimal port of the ESAPI4JS (Enterprise Security API for JavaScript) encoder.
- [escape-html](https://www.npmjs.com/package/escape-html) - Escape string for use in HTML.
- [js-string-escape](https://www.npmjs.com/package/js-string-escape) - Escape any string to be a valid JavaScript string literal between double quotes or single quotes.
- [https://github.com/chriso/validator.js](https://github.com/chriso/validator.js) - A library of string validators and sanitizers.
- [xss-filters](https://www.npmjs.com/package/xss-filters) - Just sufficient output filtering to prevent XSS!

## CSRF
- [csurf](https://www.npmjs.com/package/csurf) - Node.js CSRF protection middleware.

## Vulnerabilities and Security Advisories
- [npq](https://github.com/lirantal/npq) - Safely install packages with npm or yarn by auditing them as part of your install process.
- [snyk](https://www.npmjs.com/package/snyk) - Snyk helps you find, fix and monitor known vulnerabilities in Node.js npm, Ruby and Java dependencies, both on an ad hoc basis and as part of your CI (Build) system.
- [node-release-lines](https://www.npmjs.com/package/node-release-lines) - Introspection API for Node.js release metadata. Provides information about release lines, their relative status along with details of each release.

## Security Hardening
- [express-limiter](https://www.npmjs.com/package/express-limiter) - Rate limiting middleware for Express applications built on redis.
- [limits](https://www.npmjs.com/package/limits) - Simple express/connect middleware to set limit to upload size, set request timeout etc.


# Educational

## Hacking Playground
 - [NodeGoat](https://github.com/OWASP/NodeGoat) - The OWASP NodeGoat project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
 - [OWASP Juice Shop is an intentionally insecure webapp for security trainings written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.](https://github.com/bkimminich/juice-shop) - 

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

# Contributing
Found an awesome project, package, article, other type of resources related to Node.js Security? Send me a pull request!
Just follow the [guidelines](/CONTRIBUTING.md). Thank you!

---
say *hi* on [Twitter](https://twitter.com/liran_tal)

## License
[![CC0](http://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](http://creativecommons.org/publicdomain/zero/1.0/)


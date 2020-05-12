# egg-dd

[![NPM version][npm-image]][npm-url]
[![build status][travis-image]][travis-url]
[![Test coverage][codecov-image]][codecov-url]
[![David deps][david-image]][david-url]
[![Known Vulnerabilities][snyk-image]][snyk-url]
[![npm download][download-image]][download-url]

[npm-image]: https://img.shields.io/npm/v/egg-dd.svg?style=flat-square
[npm-url]: https://npmjs.org/package/egg-dd
[travis-image]: https://img.shields.io/travis/eggjs/egg-dd.svg?style=flat-square
[travis-url]: https://travis-ci.org/eggjs/egg-dd
[codecov-image]: https://img.shields.io/codecov/c/github/eggjs/egg-dd.svg?style=flat-square
[codecov-url]: https://codecov.io/github/eggjs/egg-dd?branch=master
[david-image]: https://img.shields.io/david/eggjs/egg-dd.svg?style=flat-square
[david-url]: https://david-dm.org/eggjs/egg-dd
[snyk-image]: https://snyk.io/test/npm/egg-dd/badge.svg?style=flat-square
[snyk-url]: https://snyk.io/test/npm/egg-dd
[download-image]: https://img.shields.io/npm/dm/egg-dd.svg?style=flat-square
[download-url]: https://npmjs.org/package/egg-dd

适用 egg.js 的钉钉服务端 SDK

## Install

```bash
$ npm i egg-dd --save
```

## Usage

```js
// {app_root}/config/plugin.js
exports.dd = {
  enable: true,
  package: 'egg-dd',
};
```

## Configuration

```js
// {app_root}/config/config.default.js
exports.dd = {
};
```

see [config/config.default.js](config/config.default.js) for more detail.

## Example

<!-- example here -->

## Questions & Suggestions

Please open an issue [here](https://github.com/eggjs/egg/issues).

## License

[MIT](LICENSE)

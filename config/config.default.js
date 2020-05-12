'use strict';

/**
 * 钉钉 SDK 插件默认配置
 * @type {{client: {custom: boolean, encodingAESKey: string, token: string}}}
 */
exports.dd = {
  client: {
    // boolean 类型，默认 true，代表应用类型为 “授权服务商开发”
    custom: false,
    // string 类型，数据加密密钥，用于消息体的加密，长度固定为43个字符，从a-z，A-Z，0-9共62个字符中选取
    encodingAESKey: 'oyBrMEjoGjdoRvjiNWM1cvKZKNOZtsHEKS0BJwl23nd',
    // string 类型，随机字符串
    token: 'fCDKpSJRUaGHr0vi',
  },
};

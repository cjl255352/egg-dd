'use strict';

const crypto = require('crypto');
const axios = require('axios');

// 钉钉服务端 API 基础请求路径
const baseURL = 'https://oapi.dingtalk.com';
// 钉钉服务端 API 免 “access_token” 白名单
const whiteList = [ 'gettoken', 'service/get_corp_token' ];
// access_token 保存时长，单位毫秒
const expires = 7000000;
// 钉钉服务端 API 返回语言
const lang = 'zh_CN';
// 钉钉服务端 API 中，分页返回数据时的分页大小
const size = 100;

class dd {
  /**
   * 构造函数
   * @param corpId
   * @param appKey
   * @param appSecret
   * @param agentId
   * @param custom，boolean 类型，默认为 false，代表应用类型为 “授权服务商开发”
   * @param encodingAESKey，string 类型，数据加密密钥，用于消息体的加密，长度固定为43个字符，从a-z，A-Z，0-9共62个字符中选取
   * @param token，string 类型，随机字符串，不能为空
   */
  constructor({ corpId, appKey, appSecret, agentId, custom, encodingAESKey, token }) {
    // 初始化应用相关参数
    this.corpId = corpId;
    this.appKey = appKey;
    this.appSecret = appSecret;
    this.agentId = agentId;
    this.custom = custom;

    // 初始化加密相关参数
    this.encodingAESKey = encodingAESKey;
    this.token = token;
    this.AESKey = Buffer.from(this.encodingAESKey + '=', 'base64');
    this.iv = this.AESKey.slice(0, 16);

    // access_token，用于请求钉钉服务端接口，有效时长7000
    this.accessToken = '';

    // 初始化 request 对象
    this.request = axios.create({
      baseURL,
      timeout: 5000,
    });
    this.request.interceptors.request.use(
      async config => {
        if (whiteList.indexOf(config.url) < 0) {
          config.params = Object.assign({ access_token: await this.getAccessToken() }, config.params);
        }
        return config;
      },
      error => {
        return Promise.reject(error);
      }
    );
    this.request.interceptors.response.use(
      response => {
        const dataAxios = response.data;
        const { errcode } = dataAxios;
        if (errcode === undefined) {
          return dataAxios;
        }
        if (errcode === 0) {
          return dataAxios;
        }
        throw new Error(dataAxios.errmsg);
      },
      error => {
        if (error && error.response) {
          switch (error.response.status) {
            case 400:
              error.message = '请求错误';
              break;
            case 401:
              error.message = '未授权，请登录';
              break;
            case 403:
              error.message = '拒绝访问';
              break;
            case 404:
              error.message = `请求地址出错: ${error.response.config.url}`;
              break;
            case 408:
              error.message = '请求超时';
              break;
            case 500:
              error.message = '服务器内部错误';
              break;
            case 501:
              error.message = '服务未实现';
              break;
            case 502:
              error.message = '网关错误';
              break;
            case 503:
              error.message = '服务不可用';
              break;
            case 504:
              error.message = '网关超时';
              break;
            case 505:
              error.message = 'http版本不受支持';
              break;
            default:
              break;
          }
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * 获取签名
   * @param timeStamp，时间戳
   * @param nonce，随机字符串，不能为空
   * @param encrypt，加密后的文本
   * @return {string}
   */
  getSignature(timeStamp, nonce, encrypt) {
    const shasum = crypto.createHash('sha1');
    const arr = [ this.token, timeStamp, nonce, encrypt ].sort();
    shasum.update(arr.join(''));
    return shasum.digest('hex');
  }

  /**
   * 解密
   * @param text，密文
   * @return {string}
   */
  decrypt(text) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.AESKey, this.iv);
    decipher.setAutoPadding(false);
    let deciphered = Buffer.concat([
      decipher.update(text, 'base64'),
      decipher.final(),
    ]);
    deciphered = this.decode(deciphered);
    const content = deciphered.slice(16);
    const length = content.slice(0, 4)
      .readUInt32BE(0);
    return content.slice(4, length + 4)
      .toString();
  }

  /**
   * 加密
   * @param text，明文
   * @return {string}
   */
  encrypt(text) {
    const random = crypto.pseudoRandomBytes(16);
    const msg = Buffer.from(text);
    const msgLength = Buffer.alloc(4);
    msgLength.writeUInt32BE(msg.length, 0);
    const $key = Buffer.from(this.corpId);
    const bufMsg = Buffer.concat([ random, msgLength, msg, $key ]);
    const encoded = this.encode(bufMsg);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.AESKey, this.iv);
    cipher.setAutoPadding(false);
    const cipheredMsg = Buffer.concat([ cipher.update(encoded), cipher.final() ]);
    return cipheredMsg.toString('base64');
  }

  /**
   * 删除解密后明文的补位字符
   * @param text
   * @return {Buffer}
   */
  decode(text) {
    let pad = text[text.length - 1];
    if (pad < 1 || pad > 32) {
      pad = 0;
    }
    return text.slice(0, text.length - pad);
  }

  /**
   * 对需要加密的明文进行填充补位
   * @param text
   * @return {Buffer}
   */
  encode(text) {
    const blockSize = 32;
    const textLength = text.length;
    const amountToPad = blockSize - (textLength % blockSize);
    const result = Buffer.alloc(amountToPad);
    result.fill(amountToPad);
    return Buffer.concat([ text, result ]);
  }

  /**
   * 获取 access_token
   * @return {Promise<string>}
   */
  async getAccessToken() {
    if (!this.accessToken) {
      if (this.custom) {
        this.accessToken = await this.getCustomAccessToken();
      } else {
        this.accessToken = await this.getDefaultAccessToken();
      }
      setTimeout(() => {
        this.accessToken = '';
      }, expires);
    }
    return this.accessToken;
  }

  /**
   * 获取 access_token，企业内部自主开发
   * @return {Promise<unknown>}
   */
  async getDefaultAccessToken() {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'gettoken',
        params: {
          appkey: this.appKey,
          appsecret: this.appSecret,
        },
      })
        .then(data => {
          resolve(data.access_token);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取 access_token，定制服务商开发
   * @return {Promise<>}
   */
  async getCustomAccessToken() {
    return new Promise((resolve, reject) => {
      const suiteTicket = '';
      const timestamp = new Date().getTime();
      const signature = crypto.createHmac('sha256', this.appSecret)
        .update(`${timestamp}\n${suiteTicket}`)
        .digest('base64');
      this.request({
        url: 'service/get_corp_token',
        method: 'post',
        params: { accessKey: this.appKey, timestamp, suiteTicket, signature },
        data: { auth_corpid: this.corpId },
      })
        .then(data => {
          resolve(data.access_token);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 注册钉钉业务事件回调
   * @param call_back_tag，array 类型，参考: https://ding-doc.dingtalk.com/doc#/serverapi2/skn8ld
   * @param url，回调地址
   * @param type，string 类型，“register” 或 “update”
   * @return {Promise<unknown>}
   */
  async bizRegister({ call_back_tag, url, type = 'register' }) {
    return new Promise(async (resolve, reject) => {
      this.request({
        url: `call_back/${type}_call_back`,
        method: 'post',
        data: {
          token: this.token,
          aes_key: this.encodingAESKey,
          call_back_tag,
          url,
        },
      })
        .then(data => {
          resolve(data.errmsg);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 回调接口触发方法
   * @param text
   * @return {
   *   timeStamp: 时间戳,
   *   msg_signature: 消息体签名,
   *   encrypt: 密文，默认加密明文为 “success”,
   *   nonce: 随机字符串
   * }
   */
  async bizCallback(text = 'success') {
    const timeStamp = new Date().getTime();
    const nonce = (Math.random() + '').substr(2);
    const encrypt = this.encrypt(text);
    const msg_signature = this.getSignature(timeStamp, nonce, encrypt);
    return {
      msg_signature,
      timeStamp,
      nonce,
      encrypt,
    };
  }

  /**
   * 获取审批实例详情
   * @param process_instance_id，string 类型，审批实例 id
   * @return {Promise<unknown>}
   */
  async getProcess(process_instance_id) {
    return new Promise(async (resolve, reject) => {
      this.request({
        url: 'topapi/processinstance/get',
        method: 'post',
        data: { process_instance_id },
      })
        .then(data => {
          resolve(data.process_instance);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取用户 userid
   * @param code，前端获取的免登授权码
   * @return {Promise<unknown>}
   */
  async getUserId(code) {
    return new Promise(async (resolve, reject) => {
      this.request({
        url: 'user/getuserinfo',
        params: { code },
      })
        .then(data => {
          resolve(data.userid);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取用户详细信息
   * @param userid
   * @return {Promise<unknown>}
   */
  async getUserInfo(userid) {
    return new Promise(async (resolve, reject) => {
      this.request({
        url: 'user/get',
        params: { userid, lang },
      })
        .then(data => {
          delete data.errcode;
          delete data.errmsg;
          resolve(data);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取离职人员信息
   * @param userid
   * @return {Promise<unknown>}
   */
  async getQuitUser(userid) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/smartwork/hrm/employee/listdimission',
        method: 'post',
        data: { userid_list: userid },
      })
        .then(data => {
          resolve(data.result[0]);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取部门用户详情，注意：不包含用户角色信息
   * @param department_id，部门 id
   * @param page，页码，默认第 1 页
   * @return {Promise<unknown>}
   */
  async getDeptUser(department_id = 1, page = 1) {
    return new Promise(async (resolve, reject) => {
      this.request({
        url: 'user/listbypage',
        params: {
          department_id,
          offset: (page - 1) * size,
          size,
          lang,
        },
      })
        .then(data => {
          resolve({
            list: data.userlist,
            pagination: {
              page,
              size,
              more: data.hasMore,
            },
          });
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取部门列表
   * @param id，部门 id
   * @param fetch_child，是否递归全部子部门
   * @return {Promise<unknown>}
   */
  async getDeptList(id = 1, fetch_child = false) {
    return new Promise(async (resolve, reject) => {
      this.request({
        url: 'department/list',
        params: { id, fetch_child, lang },
      })
        .then(data => {
          resolve(data.department);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取角色列表
   * @return {Promise<[]>}
   */
  async getRoleList() {
    const list = [];
    let page = 1;
    let more = true;
    while (more) {
      const result = await this.getRoleListByPage(page++);
      list.push(...result.list);
      more = result.hasMore;
    }
    return list;
  }

  /**
   * 获取角色列表的一页
   * @param page，页码，默认第 1 页
   * @return {Promise<unknown>}
   */
  async getRoleListByPage(page = 1) {
    return new Promise(async (resolve, reject) => {
      this.request({
        url: 'topapi/role/list',
        params: { offset: (page - 1) * size, size },
      })
        .then(data => {
          resolve(data.result);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 发送工作通知
   * @param userid_list，接收人的 id 数组
   * @param dept_id_list，接受部门的 id 数组
   * @param to_all_user，是否发送给全体员工，默认 false
   * @param msg，消息体，参考: https://ding-doc.dingtalk.com/doc#/serverapi2/iat9q8
   * @return {Promise<unknown>}
   */
  async sendNotice({ userid_list, dept_id_list, msg, to_all_user = false }) {
    const data = {
      agent_id: this.agentId,
      userid_list,
      to_all_user,
      msg,
    };
    if (dept_id_list instanceof Array && dept_id_list.length) {
      data.dept_id_list = dept_id_list;
    }
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/message/corpconversation/asyncsend_v2',
        method: 'post',
        data,
      })
        .then(data => {
          resolve(data.task_id);
        })
        .catch(err => {
          reject(err);
        });
    });
  }
}

module.exports = dd;

'use strict';

const crypto = require('crypto');
const axios = require('axios');

// 钉钉服务端 API 基础请求路径
const baseURL = 'https://oapi.dingtalk.com';
// 钉钉服务端 API 免 “access_token” 白名单
const whiteList = [ 'gettoken', 'service/get_corp_token' ];
// access_token、jsapi_ticket 保存时长，单位毫秒
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

    // access_token，用于请求钉钉服务端 API，有效时长7000
    this.accessToken = '';

    // jsapi_ticket，用于微应用前端 api 鉴权
    this.jsapiTicket = '';

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
      error => Promise.reject(error)
    );
    this.request.interceptors.response.use(
      response => {
        const dataAxios = response.data;
        const { errcode } = dataAxios;
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
              error.message = `请求地址出错：${error.response.config.url}`;
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
   * @return {Promise<unknown>}
   */
  getAccessToken() {
    return new Promise(async (resolve, reject) => {
      if (!this.accessToken) {
        try {
          if (this.custom) {
            this.accessToken = await this.getCustomAccessToken();
          } else {
            this.accessToken = await this.getDefaultAccessToken();
          }
        } catch (err) {
          reject(err);
        }
        setTimeout(() => {
          this.accessToken = '';
        }, expires);
      }
      resolve(this.accessToken);
    });
  }

  /**
   * 返回前端鉴权所需要的数据
   * @param url
   * @return {Promise<unknown>}
   */
  jsapiAuth(url) {
    return new Promise(async (resolve, reject) => {
      if (!this.jsapiTicket) {
        try {
          this.jsapiTicket = await this.getJsapiTicket();
          setTimeout(() => {
            this.jsapiTicket = '';
          }, expires);
        } catch (err) {
          reject(err);
        }
      }
      const nonceStr = (Math.random() + '').substr(2);
      const timeStamp = new Date().getTime() + '';
      const plain = `jsapi_ticket=${this.jsapiTicket}&noncestr=${nonceStr}&timestamp=${timeStamp}&url=${url}`;
      const hash = crypto.createHash('sha1');
      const signature = hash.update(Buffer.from(plain))
        .digest('hex');
      resolve({
        agentId: this.agentId,
        corpId: this.corpId,
        timeStamp,
        nonceStr,
        signature,
      });
    });
  }

  /**
   * 获取 jsapi_ticket
   * @return {Promise<unknown>}
   */
  getJsapiTicket() {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'get_jsapi_ticket',
      })
        .then(data => {
          resolve(data.ticket);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取 access_token，企业内部自主开发
   * @return {Promise<unknown>}
   */
  getDefaultAccessToken() {
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
   * @return {Promise<unknown>}
   */
  getCustomAccessToken() {
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
  bizRegister(call_back_tag, url, type = 'update') {
    return new Promise((resolve, reject) => {
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
  bizCallback(text = 'success') {
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
   * 获取回调失败的列表
   * @return {Promise<unknown>}
   */
  getCallbackFailed() {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'call_back/get_call_back_failed_result',
      })
        .then(data => {
          resolve(data.failed_list);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取审批实例详情
   * @param process_instance_id，string 类型，审批实例 id
   * @return {Promise<unknown>}
   */
  getProcess(process_instance_id) {
    return new Promise((resolve, reject) => {
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
  getUserId(code) {
    return new Promise((resolve, reject) => {
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
  getUser(userid) {
    return new Promise((resolve, reject) => {
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
   * 创建用户
   * @param data，参考: https://ding-doc.dingtalk.com/doc#/serverapi2/ege851/b6a05ccd
   * @return {Promise<unknown>}
   */
  createUser(data) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'user/create',
        method: 'post',
        data,
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
   * 更新用户信息
   * @param data，参考: https://ding-doc.dingtalk.com/doc#/serverapi2/ege851/1ce6da36
   * @return {Promise<unknown>}
   */
  updateUser(data) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'user/update',
        method: 'post',
        data,
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
   * 删除用户
   * @param userid
   * @return {Promise<unknown>}
   */
  deleteUser(userid) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'user/delete',
        params: { userid },
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
   * 获取离职人员信息
   * @param id，用户钉钉 userid 数组或字符串
   * @return {Promise<unknown>} 参考: https://ding-doc.dingtalk.com/doc#/serverapi2/fbtugn
   */
  getQuitUser(id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/smartwork/hrm/employee/listdimission',
        method: 'post',
        data: { userid_list: id instanceof Array ? id.join(',') : id },
      })
        .then(data => {
          resolve(id instanceof Array ? data.result : data.result[0]);
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
  getDeptUser(department_id = 1, page = 1) {
    return new Promise((resolve, reject) => {
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
  getDeptList(id = 1, fetch_child = false) {
    return new Promise((resolve, reject) => {
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
   * 获取部门详情
   * @param id
   * @return {Promise<unknown>}
   */
  getDept(id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'department/get',
        params: { id, lang },
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
   * 创建部门
   * @param data，参考: https://ding-doc.dingtalk.com/doc#/serverapi2/dubakq/97578482
   * @return {Promise<unknown>}
   */
  createDept(data) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'department/create',
        method: 'post',
        data,
      })
        .then(data => {
          resolve(data.id);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 更新部门
   * @param data，参考: https://ding-doc.dingtalk.com/doc#/serverapi2/dubakq/ed9c05fc
   * @return {Promise<unknown>}
   */
  updateDept(data) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'department/update',
        method: 'post',
        data,
      })
        .then(data => {
          resolve(data.id);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 删除部门
   * @param id
   * @return {Promise<unknown>}
   */
  deleteDept(id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'department/delete',
        params: { id },
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
   * 查询用户所在部门的部门路径
   * @param userId
   * @return {Promise<unknown>}
   */
  getUserDeptPath(userId) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'department/list_parent_depts',
        params: { userId },
      })
        .then(data => {
          resolve(data.department.map(e => e.reverse()));
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
  getRoleList() {
    return new Promise(async (resolve, reject) => {
      const list = [];
      let page = 1;
      let more = true;
      try {
        while (more) {
          const result = await this.getRoleListByPage(page++);
          list.push(...result.list);
          more = result.hasMore;
        }
        resolve(list);
      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * 获取角色列表的一页
   * @param page，页码，默认第 1 页
   * @return {Promise<unknown>}
   */
  getRoleListByPage(page = 1) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/role/list',
        params: { offset: (page - 1) * size, size },
      })
        .then(data => {
          resolve({
            list: data.result.list,
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
   * 获取角色下面的用户
   * @param role_id
   * @param page
   * @return {Promise<unknown>}
   */
  getRoleUser(role_id, page = 1) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/role/simplelist',
        method: 'post',
        data: { offset: (page - 1) * size, size },
      })
        .then(data => {
          resolve({
            list: data.result.list,
            pagination: {
              page,
              size,
              more: data.result.hasMore,
            },
          });
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 创建角色组
   * @param name
   * @return {Promise<unknown>}
   */
  createRoleGroup(name) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'role/add_role_group',
        method: 'post',
        data: { name },
      })
        .then(data => {
          resolve(data.groupId);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 创建角色
   * @param roleName
   * @param groupId，角色组 id，默认为 钉钉默认角色组
   * @return {Promise<unknown>}
   */
  createRole(roleName, groupId) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'role/add_role_group',
        method: 'post',
        data: { roleName, groupId },
      })
        .then(data => {
          resolve(data.roleId);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 更新角色
   * @param roleId
   * @param roleName
   * @return {Promise<unknown>}
   */
  updateRole(roleId, roleName) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'role/update_role',
        method: 'post',
        data: { roleName, roleId },
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
   * 删除角色
   * @param role_id
   * @return {Promise<unknown>}
   */
  deleteRole(role_id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/role/deleterole',
        method: 'post',
        data: { role_id },
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
   * 发送工作通知
   * @param msg，消息体，参考: https://ding-doc.dingtalk.com/doc#/serverapi2/iat9q8
   * @param to_all_user，是否发送给全体员工，默认 false
   * @param userid_list，接收人的 id 数组
   * @param dept_id_list，接受部门的 id 数组
   * @return {Promise<unknown>}
   */
  sendNotice(msg, to_all_user, userid_list, dept_id_list) {
    const data = {
      agent_id: this.agentId,
      to_all_user,
      msg,
    };
    if (!to_all_user) {
      data.userid_list = userid_list;
    }
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

  /**
   * 获取工作通知发送进度
   * @param task_id
   * @return {Promise<unknown>}
   */
  getSendProgress(task_id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/message/corpconversation/getsendprogress',
        method: 'post',
        data: { agent_id: this.agentId, task_id },
      })
        .then(data => {
          resolve(data.progress);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取工作通知发送结果
   * @param task_id
   * @return {Promise<unknown>}
   */
  getSendResult(task_id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/message/corpconversation/getsendresult',
        method: 'post',
        data: { agent_id: this.agentId, task_id },
      })
        .then(data => {
          resolve(data.send_result);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 工作通知撤销
   * @param msg_task_id
   */
  noticeRecall(msg_task_id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/message/corpconversation/recall',
        method: 'post',
        data: { agent_id: this.agentId, msg_task_id },
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
   * 发送群消息
   * @param chatid，群会话 id，参考: https://ding-doc.dingtalk.com/doc#/serverapi2/isu6nk
   * @param msg，消息体
   * @return {Promise<unknown>}
   */
  sendChat(chatid, msg) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'chat/send',
        method: 'post',
        data: { chatid, msg },
      })
        .then(data => {
          resolve(data.messageId);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取已读人员列表
   * @param messageId
   * @return {Promise<unknown>}
   */
  getReadList(messageId) {
    return new Promise(async (resolve, reject) => {
      const list = [];
      let cursor = 0;
      try {
        while (cursor !== undefined) {
          const result = await this.getReadListByPage(messageId, cursor);
          list.push(...result.list);
          cursor = result.cursor;
        }
        resolve(list);
      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * 获取已读列表的一页
   * @param messageId
   * @param cursor
   * @return {Promise<unknown>}
   */
  getReadListByPage(messageId, cursor = 0) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'chat/getReadList',
        params: { messageId, cursor, size },
      })
        .then(data => {
          resolve({
            list: data.readUserIdList,
            cursor: data.next_cursor,
          });
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 创建群
   * @param data
   * @return {Promise<unknown>}
   */
  createChat(data = {
    name: '',
    owner: '',
    useridlist: [],
    showHistoryType: 0,
    searchable: 0,
    validationType: 0,
    mentionAllAuthority: 0,
    chatBannedType: 0,
    managementType: 0,
  }) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'chat/create',
        method: 'post',
        data,
      })
        .then(data => {
          resolve(data.chatid);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 修改群会话信息
   * @param data
   * @return {Promise<unknown>}
   */
  updateChat(data) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'chat/create',
        method: 'post',
        data,
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
   * 获取群会话信息
   * @param chatid
   * @return {Promise<unknown>}
   */
  getChat(chatid) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'chat/get',
        params: { chatid },
      })
        .then(data => {
          resolve(data.chat_info);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 发送普通消息
   * @param sender
   * @param cid
   * @param msg
   * @return {Promise<unknown>}
   */
  sendMessage(sender, cid, msg) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'message/send_to_conversation',
        method: 'post',
        data: { sender, cid, msg },
      })
        .then(data => {
          resolve(data.receiver.split('|'));
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取用户可见审批模板
   * @param userid
   * @return {Promise<unknown>}
   */
  getProcessCode(userid) {
    return new Promise(async (resolve, reject) => {
      const list = [];
      let offset = 0;
      try {
        while (offset >= 0) {
          const result = await this.getProcessCodeByPage(userid, offset);
          list.push(...result.list);
          offset = result.cursor;
        }
        resolve(list);
      } catch (err) {
        reject(err);
      }
    });
  }

  /**
   * 获取用户可见审批模板的一页
   * @param userid
   * @param offset
   * @return {Promise<unknown>}
   */
  getProcessCodeByPage(userid, offset = 0) {
    const data = { offset, size };
    if (userid) {
      data.userid = userid;
    }
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/process/listbyuserid',
        method: 'post',
        data,
      })
        .then(data => {
          resolve({
            list: data.result.process_list,
            cursor: data.result.next_cursor,
          });
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 发起审批流
   * @param data
   * @return {Promise<unknown>}
   */
  createProcess(data) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/processinstance/create',
        method: 'post',
        data: { ...data, agent_id: this.agentId },
      })
        .then(data => {
          resolve(data.process_instance_id);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 分页获取审批实例 id
   * @param process_code
   * @param cursor
   * @param start_time
   * @param end_time
   * @param userid_list
   * @return {Promise<unknown>}
   */
  getProcessByPage(process_code, cursor = 0, start_time, end_time, userid_list) {
    const data = {
      process_code,
      start_time: new Date(start_time).getTime(),
      cursor,
    };
    if (end_time) {
      data.end_time = new Date(end_time).getTime();
    }
    if (userid_list instanceof Array && userid_list.length) {
      data.userid_list = userid_list.join(',');
    }
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/processinstance/listids',
        method: 'post',
        data,
      })
        .then(data => {
          resolve({
            list: data.result.list,
            cursor: data.result.next_cursor,
          });
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取用户待审批数量
   * @param userid
   */
  getTodoNum(userid) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/process/gettodonum',
        method: 'post',
        data: { userid },
      })
        .then(data => {
          resolve(data.count);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 获取钉盘空间 id
   * @param user_id
   * @return {Promise<unknown>}
   */
  getSpaceId(user_id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/processinstance/cspace/info',
        method: 'post',
        data: { user_id },
      })
        .then(data => {
          resolve(data.result.space_id);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 授权用户访问企业自定义空间
   * @param userid
   * @param domain
   * @param type
   * @param path
   * @param fileids
   * @return {Promise<unknown>}
   */
  spaceAuth(userid, domain, type, path = '/', fileids) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'cspace/grant_custom_space',
        method: 'get',
        params: { domain, type, userid, path, fileids, duration: 3600 },
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
   * 获取预览审批流附件的权限和 space_id
   * @param process_instance_id
   * @param userid
   * @param fileid_list
   * @return {Promise<unknown>}
   */
  previewFile(process_instance_id, userid, fileid_list) {
    const request = {
      agentid: this.agentId,
      process_instance_id,
      userid,
    };
    if (fileid_list.length === 1) {
      request.file_id = fileid_list[0];
    } else {
      request.fileid_list = fileid_list;
    }
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/processinstance/cspace/info',
        method: 'post',
        data: { request },
      })
        .then(data => {
          resolve(data.result.space_id);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 创建一个待办事项
   * @param data
   * @return {Promise<unknown>}
   */
  createTodo(data = {
    userid: '',
    title: '',
    url: '',
    create_time: new Date().getTime(),
    formItemList: {},
  }) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/workrecord/add',
        method: 'post',
        data,
      })
        .then(data => {
          resolve(data.record_id);
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * 更新待办
   * @param userid
   * @param record_id
   * @return {Promise<unknown>}
   */
  updateTodo(userid, record_id) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/workrecord/update',
        method: 'post',
        data: { userid, record_id },
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
   * 获取用户待办列表
   * @param userid
   * @param status
   * @param page
   * @return {Promise<unknown>}
   */
  getTodo(userid, status, page) {
    return new Promise((resolve, reject) => {
      this.request({
        url: 'topapi/workrecord/getbyuserid',
        method: 'post',
        data: {
          userid,
          status,
          offset: (page - 1) * 50,
          limit: 50,
        },
      })
        .then(data => {
          resolve({
            list: data.records.list,
            pagination: {
              page,
              size: 50,
              more: data.records.has_more,
            },
          });
        })
        .catch(err => {
          reject(err);
        });
    });
  }
}

module.exports = dd;

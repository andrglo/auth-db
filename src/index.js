'use strict';

var assert = require('assert');
var crypto = require('crypto');
var clone = require('clone');
var cuid = require('cuid');
var co = require('co');

const MIN_PASSWORD_LENGTH = 6;
const USERS = 'auth-db:users:';
const EMAILS = 'auth-db:emails:';
const ROLES = 'auth-db:roles:';
const SESSIONS = 'auth-db:sessions:';

module.exports = (redis) => {

  const throwError = (message) => {
    return redis.unwatch().then(() => {
      throw new Error(message);
    });
  };

  const saveUser = (key, user) => {
    return co(function*() {

      let taken;
      const username = user.username.toLowerCase();
      const emails = user.email && user.email.toLowerCase().split(',') || [];
      for (let email of emails) {
        const key = EMAILS + email.trim();
        yield redis.watch(key);
        const emailRecord = yield redis.hgetall(key);
        if (emailRecord.username && emailRecord.username !== username) {
          taken = email.trim();
          break;
        }
      }
      if (taken) {
        return throwError('Email ' + taken + ' already taken');
      }
      let transaction = redis.multi().hmset(key, user);
      emails.forEach((email) => {
        const key = EMAILS + email.trim();
        transaction = transaction.hsetnx(key, 'username', username);
      });

      const res = yield transaction.exec();
      return res !== null || throwError('User lock error');
    });
  };

  const saveRole = (key, role, acl) => {
    let transaction = redis.multi().hmset(key, role);
    if (acl && acl.length > 0) {
      transaction = transaction
        .del(key + ':acl')
        .sadd(key + ':acl', aclToSet(acl));
    }
    return transaction
      .exec()
      .then(res => res !== null || throwError('Role lock error', res));
  };

  return {

    users: {
      get: function(username) {
        return redis.hgetall(USERS + username.toLowerCase())
          .then(user => {
            if (user.roles) {
              user.roles = user.roles.split(',');
            }
            delete user.password;
            delete user.salt;
            return user;
          });
      },
      create: function(user) {
        return Promise.resolve().then(function() {
          assert(user.username, 'Missing username');
          assert(user.password, 'Missing password');
          user = encryptPassword(user);
          const key = USERS + user.username.toLowerCase();
          return redis.watch(key)
            .then(() => redis
              .hmget(key, 'username')
              .then(res => res[0] === null ? saveUser(key, user) : throwError('User name already taken')));
        });
      },
      update: function(user, username) {
        return Promise.resolve().then(function() {
          assert(username, 'Missing username');
          user = encryptPassword(user);
          username = username.toLowerCase();
          const key = USERS + username;
          return redis.watch(key)
            .then(() => redis.hgetall(key)
              .then((record) => {
                const found = record.username && record.username.toLowerCase() === username;
                if (!found) {
                  return throwError('User not found');
                }
                record = Object.assign(record, user);
                return saveUser(key, record);
              }));
        });
      },
      checkPassword: function(credentials) {
        return redis.hgetall(USERS + credentials.username.toLowerCase())
          .then(user => {
            return user.password === hashPassword(user.salt, credentials.password);
          });
      },
      emails: function(username) {
        username = username.toLowerCase();
        return redis.hgetall(USERS + username)
          .then(user => {
            return co(function*() {
              const emailList = user.email && user.email.toLowerCase().split(',') || [];
              let emails = [];
              for (let email of emailList) {
                const key = EMAILS + email.trim();
                const emailRecord = yield redis.hgetall(key);
                if (emailRecord.username && emailRecord.username === username) {
                  emails.push(emailRecord);
                }
              }
              return emails;
            });
          });
      }
    },
    email: {
      get: function(email) {
        return redis.hgetall(EMAILS + email.toLowerCase());
      },
      update: function(data, email) {
        return Promise.resolve().then(function() {
          assert(email, 'Missing email');
          email = email.toLowerCase();
          const key = EMAILS + email;
          return redis.watch(key)
            .then(() => redis.hgetall(key)
              .then((record) => {
                const found = record.username;
                if (!found) {
                  return throwError('Email not found');
                }
                if (record.username !== data.username) {
                  return throwError('User name is missing or do not match');
                }
                record = Object.assign(record, data);
                return redis
                    .multi()
                    .hmset(key, record)
                    .exec()
                    .then(res => res !== null || throwError('Email update lock error'));
              }));
        });
      }
    },
    roles: {
      get: function(name) {
        var key = ROLES + name.toLowerCase();
        return redis.hgetall(key)
          .then(function(record) {
            return redis.smembers(key + ':acl')
              .then(function(res) {
                if (res) {
                  record.acl = setToAcl(res);
                }
                return record;
              });
          });
      },
      create: function(role) {

        return Promise.resolve().then(function() {
          assert(role.name, 'Role name is missing');
          assert(role.acl === void 0 || Array.isArray(role.acl), 'acl must be an array');
          role = clone(role);
          var acl = role.acl;
          delete role.acl;
          var key = ROLES + role.name.toLowerCase();
          return redis.watch(key)
            .then(() => redis
              .hmget(key, 'name')
              .then(res => res[0] === null ?
                saveRole(key, role, acl) :
                throwError('Role already exists')));
        });
      },
      update: function(role, name) {

        return Promise.resolve().then(function() {
          assert(name, 'Role name is missing');
          assert(role.acl === void 0 || Array.isArray(role.acl), 'acl must be an array');
          role = clone(role);
          var acl = role.acl;
          delete role.acl;
          name = name.toLowerCase();
          var key = ROLES + name;
          return redis.watch(key)
            .then(() => redis.hgetall(key)
              .then((record) => {
                const found = record.name && record.name.toLowerCase() === name;
                if (!found) {
                  return throwError('Role not found');
                }
                record = Object.assign(record, role);
                return saveRole(key, record, acl);
              }));
        });
      },
      hasPermission: function(roles, resource, method) {

        var checkRole = name => {
          if (typeof name !== 'string') {
            return false;
          }
          var key = ROLES + name.toLowerCase() + ':acl';
          return typeof method === 'string' ?
            redis.sismember(key, resource + method.toUpperCase())
              .then(res => res || redis.sismember(key, resource + '*'))
              .then(res => res === 1) :
            redis.sismember(key, resource + '*')
              .then(res => res === 1);
        };

        resource = resource.toLowerCase() + ':';
        roles = Array.isArray(roles) ? roles : [roles];

        return roles.reduce((promise, role) =>
          promise.then(res =>
            res === true ? res : checkRole(role)), Promise.resolve(false));

      }
    },
    sessions: {
      get: function(id) {
        return redis.hgetall(SESSIONS + id);
      },
      create: function(expiresInSeconds, data) {
        var id = cuid();
        var key = SESSIONS + id;
        return redis.hmset(key, data)
          .then(function(res) {
            if (expiresInSeconds) {
              return redis.expire(key, expiresInSeconds)
                .then(function(res) {
                  return res === 1 ? id : null;
                });
            }
            return res === 'OK' ? id : null;
          });
      },
      destroy: function(id) {
        assert(typeof id === 'string', 'session id must be a string');
        return redis.del(SESSIONS + id)
          .then(function(res) {
            return res === 1;
          });
      }
    }

  };
};

/**
 * Encrypt password
 *
 * @private
 * @param user
 */
function encryptPassword(user) {
  if (user.password) {
    assert(user.password.length >= MIN_PASSWORD_LENGTH, 'password should have a minimum of ' + MIN_PASSWORD_LENGTH + ' characters');
    user = clone(user);
    user.salt = crypto.randomBytes(16).toString('base64');
    user.password = hashPassword(user.salt, user.password);
  }
  return user;
}

/**
 * Hash password
 *
 * @private
 * @param salt
 * @param password
 * @returns {*|string}
 */
function hashPassword(salt, password) {
  return crypto.pbkdf2Sync(password, salt, 10000, 64).toString('base64');
}

function aclToSet(acl) {
  var set = [];
  acl.forEach(function(aci) {
    if (typeof aci === 'string') {
      aci = { resource: aci };
    }
    assert(aci.resource, 'Resource must be informed');
    aci.methods = aci.methods || ['*'];
    aci.methods = Array.isArray(aci.methods) ? aci.methods : [aci.methods];
    aci.methods.forEach(function(method) {
      set.push(aci.resource.toLowerCase() + ':' + method.toUpperCase());
    });
  });
  return set;
}

function setToAcl(set) {
  var acl = [];
  set.forEach(function(str) {
    var elements = str.split(':');
    var aci = acl.filter(obj => obj.resource === elements[0]);
    if (aci.length === 0) {
      acl.push({
        resource: elements[0],
        methods: [elements[1]]
      });
    } else {
      aci[0].methods.push(elements[1]);
    }
  });
  return acl;
}

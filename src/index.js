'use strict';

var assert = require('assert');
var crypto = require('crypto');
var cuid = require('cuid');

const MIN_PASSWORD_LENGTH = 6;
const USERS = 'auth-db:users:';
const ROLES = 'auth-db:roles:';
const SESSIONS = 'auth-db:sessions:';

module.exports = (redis) => {

  const throwError = (message) => {
    return redis.unwatch().then(() => {
      throw new Error(message)
    });
  };

  const saveRole = (key, role, acl) => {
    let transaction = redis.multi().hmset(key, role);
    if (acl && acl.length > 0) {
      transaction = transaction
        .del(key + ':acl')
        .sadd(key + ':acl', aclToSet(acl))
    }
    return transaction
      .exec()
      .then(res => res !== null || throwError('Role update lock error', res))
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
          encryptPassword(user);
          const key = USERS + user.username.toLowerCase();
          return redis.watch(key)
            .then(() => redis
              .hmget(key, 'username')
              .then(res => res[0] === null ?
                redis
                  .multi()
                  .hmset(key, user)
                  .exec()
                  .then(res => res !== null || throwError('User creation lock error'))
                : throwError('User name already taken')));
        });
      },
      update: function(user, username) {
        return Promise.resolve().then(function() {
          assert(username, 'missing username');
          encryptPassword(user);
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
                return redis
                  .multi()
                  .hmset(key, record)
                  .exec()
                  .then((res) => res !== null || throwError('User update lock error'));
              }));
        });
      },
      checkPassword: function(credentials) {
        return redis.hgetall(USERS + credentials.username.toLowerCase())
          .then(user => {
            return user.password === hashPassword(user.salt, credentials.password);
          });
      }
    },
    //todo always throw on error
    //todo use email as secondary key
    //todo arguments are immutable
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

  }
};

/**
 * Encrypt password
 *
 * @private
 * @param user
 */
function encryptPassword(user) {
  if (!user.password) {
    return;
  }
  assert(user.password.length >= MIN_PASSWORD_LENGTH, 'password should have a minimum of ' + MIN_PASSWORD_LENGTH + ' characters');
  user.salt = crypto.randomBytes(16).toString('base64');
  user.password = hashPassword(user.salt, user.password);
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

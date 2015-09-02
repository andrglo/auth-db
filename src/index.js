var assert = require('assert');
var _ = require('lodash');
var crypto = require('crypto');
var uuid = require('uuid');

const MIN_PASSWORD_LENGTH = 6;

/**
 * Store user, roles and sessions data. Establish a username
 * for the main user, owner, that should be the first to be
 * included and cannot be deleted. It' automatically
 * granted an admin attribute that cannot be removed
 *
 * @module db
 * @param {object} redis - A redis open connection using
 * packages node-redis or ioredis
 * @returns {object}
 */
module.exports = function(redis) {

  const USERS = 'users:';
  const ROLES = 'roles:';
  const SESSIONS = 'sessions:';

  //todo queries for user and roles
  return {
    /**
     * Handle users instances
     *
     * @exports db.users
     */
    users: {
      /**
       * Get a user by username
       *
       * @param username
       * @returns {Promise} The user
       */
      get: function(username) {
        return redis.hgetall(USERS + username.toLowerCase());
      },
      /**
       * Create a user. Require at least a property
       * username and password
       *
       * @param user
       * @returns {Promise} true if success
       */
      create: function(user) {
        return Promise.resolve().then(function() {
          assert(user.username, 'missing username');
          assert(user.password, 'missing password');
          encryptPassword(user);
          return redis.hmset(USERS + user.username.toLowerCase(), user)
              .then(function(res) {
                return res === 'OK';
              });
        });
      },
      /**
       * Update a user
       *
       * @param user
       * @param username
       * @returns {Promise} true if success
       */
      update: function(user, username) {
        return Promise.resolve().then(function() {
          assert(username, 'missing username');
          encryptPassword(user);
          username = username.toLowerCase();
          return redis.hgetall(USERS + username)
              .then(function(record) {
                assert(record.username && record.username.toLowerCase() === username, 'user not found');
                record = _.extend(record, user);
                return redis.hmset(USERS + username, record)
                    .then(function(res) {
                      return res === 'OK';
                    });
              });
        });
      },
      /**
       * Check the user password
       *
       * @param password
       * @param user
       * @returns {boolean}
       */
      checkPassword: function(password, user) {
        return user.password === hashPassword(user.salt, password);
      }
    },
    /**
     * Handle roles instances
     *
     * @exports db.roles
     */
    roles: {
      /**
       * Get a role by name
       *
       * @param name
       * @returns {Promise} The role
       */
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
      /**
       * Create a new role
       *
       * @param role
       * @returns {Promise} boolean
       */
      create: function(role) {
        return Promise.resolve().then(function() {
          assert(role.name, 'missing name');
          assert(role.acl === void 0 || _.isArray(role.acl), 'acl must be an array');
          var acl = role.acl;
          delete role.acl;
          var key = ROLES + role.name.toLowerCase();
          return redis.hmset(key, role)
              .then(function(res) {
                if (acl && acl.length > 0) {
                  return redis.sadd(key + ':acl', aclToSet(acl))
                      .then(function(res) {
                        return res > 0;
                      });
                }
                return res === 'OK';
              });
        });
      },
      /**
       * Update a role
       *
       * @param role
       * @param name
       * @returns {Promise} boolean
       */
      update: function(role, name) {
        return Promise.resolve().then(function() {
          assert(name, 'missing name');
          assert(role.acl === void 0 || _.isArray(role.acl), 'acl must be an array');
          var acl = role.acl;
          delete role.acl;
          name = name.toLowerCase();
          return redis.hgetall(ROLES + name)
              .then(function(record) {
                assert(record.name && record.name.toLowerCase() === name, 'role not found');
                record = _.extend(record, role);
                var key = ROLES + name;
                return redis.hmset(key, record)
                    .then(function(res) {
                      if (acl && acl.length > 0) {
                        return redis.del(key + ':acl')
                            .then(function() {
                              return redis.sadd(key + ':acl', aclToSet(acl))
                                  .then(function(res) {
                                    return res > 0;
                                  });
                            });
                      }
                      return res === 'OK';
                    });
              });
        });
      },
      hasPermission: function(name, resource, method) {
        var key = ROLES + name.toLowerCase() + ':acl';
        resource = resource.toLowerCase() + ':';
        return typeof method === 'string' ?
            redis.sismember(key, resource + method.toUpperCase())
                .then(function(res) {
                  return res || redis.sismember(key, resource + '*');
                })
                .then(function(res) {
                  return res === 1;
                }) :
            redis.sismember(key, resource + '*')
                .then(function(res) {
                  return res === 1;
                });
      }
    },
    /**
     * Handle sessions instances
     *
     * @exports db.sessions
     */
    sessions: {
      /**
       * Get a session by id
       *
       * @param id
       * @returns {Promise} The session
       */
      get: function(id) {
        return redis.hgetall(SESSIONS + id);
      },
      /**
       * Create a new session
       *
       * @param expiresInSeconds
       * @param data
       * @returns {Promise} Id of the created session
       */
      create: function(expiresInSeconds, data) {
        var id = uuid.v4();
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
      /**
       * Deletes a session
       *
       * @param id
       * @returns {Promise} boolean
       */
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
  if (!user.password) return;
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
      aci = {resource: aci};
    }
    assert(aci.resource, 'Resource must be informed');
    aci.methods = aci.methods || ['*'];
    aci.methods = _.isArray(aci.methods) ? aci.methods : [aci.methods];
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
    var aci = _.find(acl, 'resource', elements[0]);
    if (!aci) {
      aci = {
        resource: elements[0],
        methods: []
      };
      acl.push(aci);
    }
    aci.methods.push(elements[1]);
  });
  return acl;
}

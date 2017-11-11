const assert = require('assert')
const crypto = require('crypto')
const clone = require('clone')
const cuid = require('cuid')
const co = require('co')
const emailValidator = require('email-validator')

const MIN_PASSWORD_LENGTH = 6
const USERS = 'auth-db:users:'
const EMAILS = 'auth-db:emails:'
const ROLES = 'auth-db:roles:'
const SESSIONS = 'auth-db:sessions:'

module.exports = (redis, options) => {
  options = options || {}
  options = {
    saltLength: options.saltLength || 16,
    iterations: options.iterations || 10000,
    keylen: options.keylen || 64,
    digest: options.digest || 'sha1'
  }

  const throwError = message => {
    return redis.unwatch().then(() => {
      throw new Error(message)
    })
  }

  const createUser = (key, user) => {
    return co(function *() {
      let taken
      const username = user.username.toLowerCase()
      const emails = user.email && user.email.toLowerCase().split(',') || []
      for (let email of emails) {
        email = email.trim().toLowerCase()
        if (!emailValidator.validate(email)) {
          return throwError(`Email ${email} is invalid`)
        }
        const key = EMAILS + email
        yield redis.watch(key)
        const emailRecord = yield redis.hgetall(key)
        if (emailRecord.username) {
          taken = email.trim()
          break
        }
      }
      if (taken) {
        return throwError('Email ' + taken + ' already taken')
      }
      let transaction = redis.multi().hmset(key, user)
      emails.forEach(email => {
        const key = EMAILS + email.trim()
        transaction = transaction.hsetnx(key, 'username', username)
      })

      const res = yield transaction.exec()
      return res !== null || throwError('User lock error')
    })
  }

  const addEmail = (email, username) => co(function *() {
    let key = USERS + username
    yield redis.watch(key)
    const user = yield redis.hgetall(key)
    if (user.email) {
      user.email = user.email.split(',').concat(email).join(',')
    } else {
      user.email = email
    }

    let transaction = redis.multi().hmset(key, user)
    key = EMAILS + email.trim()
    transaction = transaction.hsetnx(key, 'username', username)

    const res = yield transaction.exec()
    return res !== null || throwError('User/email lock error')
  })

  const removeEmail = (email, username) => co(function *() {
    let key = USERS + username
    yield redis.watch(key)
    const user = yield redis.hgetall(key)
    const emails = user.email && user.email.split(',') || []
    const index = emails.indexOf(email)
    if (index > -1) {
      emails.splice(index, 1)
    }
    user.email = emails.join(',')

    let transaction = redis.multi().hmset(key, user)
    key = EMAILS + email.trim()
    transaction = transaction.del(key)

    const res = yield transaction.exec()
    return res !== null || throwError('User/email lock error')
  })

  const saveRole = (key, role, acl) => {
    let transaction = redis.multi().hmset(key, role)
    if (acl && acl.length > 0) {
      transaction = transaction
        .del(key + ':acl')
        .sadd(key + ':acl', aclToSet(acl))
    }
    return transaction
      .exec()
      .then(res => res !== null || throwError('Role lock error', res))
  }

  return {

    users: {
      get: function(username) {
        return redis.hgetall(USERS + username.toLowerCase())
          .then(user => {
            if (user.roles) {
              user.roles = user.roles.split(',')
            }
            delete user.password
            delete user.salt
            return user
          })
      },
      create: function(user) {
        return Promise.resolve().then(function() {
          assert(user.username, 'Missing username')
          assert(user.password, 'Missing password')
          return encryptPassword(user, options)
            .then(user => {
              const key = USERS + user.username.toLowerCase()
              return redis.watch(key)
                .then(() => redis
                  .hmget(key, 'username')
                  .then(res => res[0] === null ? createUser(key, user)
                    : throwError('User name already taken')))
            })
        })
      },
      update: function(user, username) {
        return Promise.resolve().then(function() {
          assert(username, 'Missing username')
          assert(!user.email, 'To update/create/delete a email use email api')
          return encryptPassword(user, options).then(user => {
            username = username.toLowerCase()
            const key = USERS + username
            return redis.watch(key)
              .then(() => redis.hgetall(key)
                .then(record => {
                  const found = record.username
                                && record.username.toLowerCase() === username
                  if (!found) {
                    return throwError('User not found')
                  }
                  record = Object.assign(record, user)
                  return redis
                    .multi()
                    .hmset(key, record)
                    .exec()
                    .then(res => res !== null
                                 || throwError('User update lock error'))
                }))
          })
        })
      },
      checkPassword: function(credentials) {
        return redis.hgetall(USERS + credentials.username.toLowerCase())
          .then(user => hashPassword(credentials.password, user.salt, options)
            .then(password => password === user.password))
      },
      emails: function(username) {
        username = username.toLowerCase()
        return redis.hgetall(USERS + username)
          .then(user => {
            return co(function *() {
              const emailList = user.email
                                && user.email.toLowerCase().split(',') || []
              let emails = []
              for (let email of emailList) {
                email = email.trim()
                const key = EMAILS + email
                const emailRecord = yield redis.hgetall(key)
                if (emailRecord.username && emailRecord.username === username) {
                  emails.push(Object.assign({}, emailRecord, {email}))
                }
              }
              return emails
            })
          })
      }
    },
    email: {
      get: function(email) {
        return redis.hgetall(EMAILS + email.toLowerCase())
      },
      add: function(email, username) {
        return Promise.resolve().then(function() {
          email = email.trim().toLowerCase()
          if (!emailValidator.validate(email)) {
            return throwError(`Email ${email} is invalid`)
          }
          const key = EMAILS + email
          return redis.watch(key)
            .then(() => redis.hgetall(key)
              .then(record => {
                const found = record.username
                if (found) {
                  return throwError(`Email ${email} already exist`)
                }
                return addEmail(email, username.toLowerCase())
              }))
        })
      },
      update: function(data, email) {
        return Promise.resolve().then(function() {
          assert(email, 'Missing email')
          email = email.trim().toLowerCase()
          const key = EMAILS + email
          return redis.watch(key)
            .then(() => redis.hgetall(key)
              .then(record => {
                const found = record.username
                if (!found) {
                  return throwError('Email not found')
                }
                if (record.username !== data.username) {
                  return throwError('User name is missing or do not match')
                }
                record = Object.assign(record, data)
                return redis
                  .multi()
                  .hmset(key, record)
                  .exec()
                  .then(res => res !== null
                               || throwError('Email update lock error'))
              }))
        })
      },
      remove: function(email, username) {
        return Promise.resolve().then(function() {
          email = email.trim().toLowerCase()
          username = username.toLowerCase()
          if (!emailValidator.validate(email)) {
            return throwError(`Email ${email} is invalid`)
          }
          const key = EMAILS + email
          return redis.watch(key)
            .then(() => redis.hgetall(key)
              .then(record => {
                const found = record.username
                if (!found) {
                  return throwError(`Email ${email} not found`)
                }
                if (record.username !== username) {
                  return throwError(`Email ${email} not registered for user ${username}`)
                }
                if (record.verified) {
                  return throwError(`Email ${email} has been verified and cannot be removed`)
                }
                return removeEmail(email, username)
              }))
        })
      }
    },
    roles: {
      get: function(name) {
        const key = ROLES + name.toLowerCase()
        return redis.hgetall(key)
          .then(function(record) {
            return record.name ? redis.smembers(key + ':acl')
              .then(function(res) {
                if (res) {
                  record.acl = setToAcl(res)
                }
                return record
              }) : record
          })
      },
      list: function(prefix) {
        prefix = prefix || ''
        return redis
          .keys(`${ROLES}${prefix.toLowerCase()}*`)
          .filter(role => role.indexOf(':acl') === -1)
          .then(keys => keys.map(key => key.replace(ROLES, '')))
      },
      create: function(role) {
        return Promise.resolve().then(function() {
          assert(role.name, 'Role name is missing')
          assert(role.acl === void 0
                 || Array.isArray(role.acl), 'acl must be an array')
          role = clone(role)
          const acl = role.acl
          delete role.acl
          const key = ROLES + role.name.toLowerCase()
          return redis.watch(key)
            .then(() => redis
              .hmget(key, 'name')
              .then(res => res[0] === null ? saveRole(key, role, acl)
                : throwError('Role already exists')))
        })
      },
      update: function(role, name) {
        return Promise.resolve().then(function() {
          assert(name, 'Role name is missing')
          assert(role.acl === void 0
                 || Array.isArray(role.acl), 'acl must be an array')
          role = clone(role)
          const acl = role.acl
          delete role.acl
          name = name.toLowerCase()
          const key = ROLES + name
          return redis.watch(key)
            .then(() => redis.hgetall(key)
              .then(record => {
                const found = record.name && record.name.toLowerCase() === name
                if (!found) {
                  return throwError('Role not found')
                }
                record = Object.assign(record, role)
                return saveRole(key, record, acl)
              }))
        })
      },
      hasPermission: function(roles, resource, method) {
        const checkRole = name => {
          if (typeof name !== 'string') {
            return false
          }
          const key = ROLES + name.toLowerCase() + ':acl'
          return typeof method === 'string'
            ? redis.sismember(key, resource + method.toUpperCase())
              .then(res => res || redis.sismember(key, resource + '*'))
              .then(res => res === 1)
            : redis.sismember(key, resource + '*')
              .then(res => res === 1)
        }

        resource = resource.toLowerCase() + ':'
        roles = Array.isArray(roles) ? roles : [roles]

        return roles.reduce((promise, role) =>
          promise.then(res =>
            res === true ? res : checkRole(role)), Promise.resolve(false))
      }
    },
    sessions: {
      get: function(username, id) {
        return redis.hgetall(SESSIONS + `${username}:${id}`)
      },
      create: function(username, data, expiresInSeconds) {
        const id = cuid()
        const key = SESSIONS + `${username}:${id}`
        return redis.hmset(key, data)
          .then(function(res) {
            if (expiresInSeconds) {
              return redis.expire(key, expiresInSeconds)
                .then(function(res) {
                  return res === 1 ? id : null
                })
            }
            return res === 'OK' ? id : null
          })
      },
      destroy: function(username, id) {
        return redis.del(SESSIONS + `${username}:${id}`)
          .then(function(res) {
            return res === 1
          })
      },
      reset: function(username) {
        const stream = redis.scanStream({
          match: `${SESSIONS}${username}:*`
        })
        return new Promise(
          resolve => {
            const keys = []
            stream.on('data', resultKeys => {
              for (let i = 0; i < resultKeys.length; i++) {
                keys.push(resultKeys[i])
              }
            })
            stream.on('end', () => resolve(keys))
          }
        )
          .then(keys => Promise.all(keys.map(key => redis.del(key))))
          .then(() => true)
      }
    }

  }
}

function encryptPassword(user, options) {
  return Promise.resolve()
    .then(() => {
      if (user.password) {
        assert(user.password.length
               >= MIN_PASSWORD_LENGTH, 'password should have a minimum of '
                                       + MIN_PASSWORD_LENGTH + ' characters')
        user = clone(user)
        user.salt = crypto.randomBytes(options.saltLength).toString('base64')
        return hashPassword(user.password, user.salt, options)
          .then(password => {
            user.password = password
            return user
          })
      }
      return user
    })
}

function hashPassword(password, salt, options) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      password,
      salt,
      options.iterations,
      options.keylen,
      options.digest,
      (error, key) => {
        if (error) {
          return reject(error)
        }
        resolve(key.toString('base64'))
      })
  })
}

function aclToSet(acl) {
  const set = []
  acl.forEach(function(aci) {
    if (typeof aci === 'string') {
      aci = {resource: aci}
    }
    assert(aci.resource, 'Resource must be informed')
    aci.methods = aci.methods || ['*']
    aci.methods = Array.isArray(aci.methods) ? aci.methods : [aci.methods]
    aci.methods.forEach(function(method) {
      set.push(aci.resource.toLowerCase() + ':' + method.toUpperCase())
    })
  })
  return set
}

function setToAcl(set) {
  const acl = []
  set.forEach(function(str) {
    const elements = str.split(':')
    const aci = acl.filter(obj => obj.resource === elements[0])
    if (aci.length === 0) {
      acl.push({
        resource: elements[0],
        methods: [elements[1]]
      })
    } else {
      aci[0].methods.push(elements[1])
    }
  })
  return acl
}

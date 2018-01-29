const assert = require('assert')
const crypto = require('crypto')
const uuidv4 = require('uuid/v4')
const deburr = require('lodash.deburr')
const emailValidator = require('email-validator')

const MIN_PASSWORD_LENGTH = 8
const MAX_PASSWORD_LENGTH = 60
const MAX_INACTIVITY_IN_SECONDS =
  process.env.NODE_ENV === 'test'
    ? 1
    : 60 * 60 * 24 * 10 // 10 days
const USERS = 'auth-db:users:'
const EMAILS = 'auth-db:emails:'
const ROLES = 'auth-db:roles:'
const SESSIONS = 'auth-db:sessions:'

const VERIFIED_FIELD = 'verifiedAt'

const normalize = username => deburr(username).toLowerCase().trim()

function AuthDbError(message, code) {
  this.name = 'AuthDbError'
  this.message = message
  this.code = code
}

AuthDbError.prototype = Object.create(Error.prototype)
AuthDbError.prototype.constructor = AuthDbError

module.exports = (redis, options) => {
  options = options || {}
  options = {
    saltLength: options.saltLength || 16,
    iterations: options.iterations || 10000,
    keylen: options.keylen || 64,
    digest: options.digest || 'sha256',
    timestamp: options.timestamp !== false,
    passwordRequired: options.passwordRequired !== false
  }

  const throwError = (message, code) => {
    return redis.unwatch().then(() => {
      throw new AuthDbError(message, code)
    })
  }

  const createUser = async (key, user) => {
    let taken
    const emails = user.email && user.email.toLowerCase().split(',') || []
    for (let email of emails) {
      email = email.trim().toLowerCase()
      if (!emailValidator.validate(email)) {
        return throwError(`Email ${email} is invalid`)
      }
      const key = EMAILS + email
      await redis.watch(key)
      const emailRecord = await redis.hgetall(key)
      if (emailRecord.username) {
        taken = email.trim()
        break
      }
    }
    if (taken) {
      return throwError('Email ' + taken + ' already taken')
    }
    if (options.timestamp) {
      user.createdAt = new Date().toISOString()
      user.updatedAt = user.createdAt
    }
    let transaction = redis.multi().hmset(key, user)
    emails.forEach(email => {
      const key = EMAILS + email.trim()
      transaction = transaction.hsetnx(key, 'username', user.username)
    })
    const res = await transaction.exec()
    return res !== null || throwError('User lock error')
  }

  const addEmail = async (email, username) => {
    let key = USERS + username
    await redis.watch(key)
    const user = await redis.hgetall(key)
    if (user.email) {
      user.email = user.email.split(',').concat(email).join(',')
    } else {
      user.email = email
    }

    let transaction = redis.multi().hmset(key, user)
    key = EMAILS + email.trim()
    transaction = transaction.hsetnx(key, 'username', username)

    const res = await transaction.exec()
    return res !== null || await throwError('User/email lock error')
  }

  const removeEmail = async (email, username) => {
    let key = USERS + username
    await redis.watch(key)
    const user = await redis.hgetall(key)
    const emails = user.email && user.email.split(',') || []
    const index = emails.indexOf(email)
    if (index > -1) {
      emails.splice(index, 1)
    }
    user.email = emails.join(',')

    let transaction = redis.multi().hmset(key, user)
    key = EMAILS + email.trim()
    transaction = transaction.del(key)

    const res = await transaction.exec()
    return res !== null || await throwError('User/email lock error')
  }

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
        return redis.hgetall(USERS + normalize(username))
          .then(user => {
            if (user.roles) {
              user.roles = user.roles.split(',')
            }
            delete user.password
            delete user.salt
            return user
          })
      },
      async create(user) {
        assert(user.username, 'Missing username')
        user = Object.assign({}, user)
        if (options.passwordRequired) {
          assert(user.password, 'Missing password')
        }
        if (user.password) {
          user = await encryptPassword(user, options)
        }
        user.username = normalize(user.username)
        const key = USERS + user.username
        await redis.watch(key)
        const res = await redis.hmget(key, 'username')
        await (
          res[0] === null
            ? createUser(key, user)
            : throwError('User name already taken', 'userExists')
        )
        return user.username
      },
      update: async (user, username) => {
        assert(username, 'Missing username')
        assert(!user.email, 'To update/create/delete a email use email api')
        user = Object.assign({}, user)
        if (user.password) {
          user = await encryptPassword(user, options)
        }
        const key = USERS + normalize(username)
        await redis.watch(key)
        let record = await redis.hgetall(key)
        const found = Boolean(record.username)
        if (!found) {
          return await throwError('User not found')
        }
        if (options.timestamp) {
          user.updatedAt = new Date().toISOString()
        }
        record = Object.assign(record, user)
        const res = await redis
          .multi()
          .hmset(key, record)
          .exec()
        return res !== null || await throwError('User update lock error')
      },
      remove: async username => {
        assert(username, 'Missing username')
        const userKey = USERS + normalize(username)
        await redis.watch(userKey)
        const [requests, email] = await redis.hmget(userKey, 'requests', 'email')
        if (Number(requests) > 0) {
          await throwError('User cannot be removed', 'activeUser')
        }
        const emails = email ? email.split(',') : []
        const multi = await redis.multi()
        for (const email of emails) {
          multi.del(EMAILS + email.trim())
        }
        const res = await multi
          .del(userKey)
          .exec()
        return res !== null || await throwError('Remove user lock error')
      },
      checkPassword: function(credentials) {
        return redis.hgetall(USERS + credentials.username.toLowerCase())
          .then(user => hashPassword(credentials.password, user.salt, options)
            .then(password => password === user.password))
      },
      emails: async username => {
        username = normalize(username)
        const user = await redis.hgetall(USERS + username)
        const emailList = user.email
                          && user.email.toLowerCase().split(',') || []
        const emails = []
        for (let email of emailList) {
          email = email.trim()
          const key = EMAILS + email
          const emailRecord = await redis.hgetall(key)
          if (emailRecord.username && emailRecord.username === username) {
            emails.push(Object.assign({}, emailRecord, {email}))
          }
        }
        return emails
      }
    },
    email: {
      get: function(email) {
        return redis.hgetall(EMAILS + email.toLowerCase())
      },
      add: async (email, username) => {
        email = email.trim().toLowerCase()
        if (!emailValidator.validate(email)) {
          return await throwError(`Email ${email} is invalid`)
        }
        const key = EMAILS + email
        await redis.watch(key)
        const record = await redis.hgetall(key)
        const found = Boolean(record.username)
        return await (
          found
            ? throwError(`Email ${email} already exist`)
            : addEmail(email, normalize(username))
        )
      },
      async setVerified(email) {
        const key = EMAILS + email
        let verified = await redis.hget(key, VERIFIED_FIELD)
        if (!verified) {
          verified = new Date().toISOString()
          await redis.hmset(key, VERIFIED_FIELD, verified)
        }
        return verified
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
          role = Object.assign({}, role)
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
          role = Object.assign({}, role)
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
      get(username, id) {
        return redis.hgetall(SESSIONS + `${username}:${id}`)
      },
      async create(
        username,
        data = {},
        maxInactivityInSeconds = MAX_INACTIVITY_IN_SECONDS
      ) {
        const id = uuidv4()
        const sessionKey = SESSIONS + `${username}:${id}`
        data = Object.assign({createdAt: new Date().toISOString()}, data)
        const res = await redis.hmset(sessionKey, data)
        await redis.expire(sessionKey, maxInactivityInSeconds)
        return res === 'OK' ? id : null
      },
      async validate(username,
        id,
        maxInactivityInSeconds = MAX_INACTIVITY_IN_SECONDS
      ) {
        const now = Date.now()
        const userKey = USERS + username
        const licenseExpireOn = await redis.hget(userKey, 'expireOn')
        if (licenseExpireOn && now > Number(licenseExpireOn)) {
          throw new AuthDbError('User license expired', 'licenseExpired')
        }
        const sessionKey = `${SESSIONS}${username}:${id}`
        if (!await redis.exists(sessionKey)) {
          throw new AuthDbError('Session not found', 'notFound')
        }
        await redis.expire(sessionKey, maxInactivityInSeconds)
        await redis.hincrby(userKey, 'requests', 1)
        await redis.hincrby(sessionKey, 'requests', 1)
        await redis.hmset(userKey, 'lastRequest', now)
        await redis.hmset(sessionKey, 'lastRequest', now)
      },
      async destroy(username, id) {
        return await redis.del(SESSIONS + `${username}:${id}`) === 1
      },
      reset(username) {
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
      assert(user.password.length
             >= MIN_PASSWORD_LENGTH, 'password should have a minimum of '
                                     + MIN_PASSWORD_LENGTH + ' characters')
      assert(user.password.length
             <= MAX_PASSWORD_LENGTH, 'password should have a maximum of '
                                     + MAX_PASSWORD_LENGTH + ' characters')
      user.salt = crypto.randomBytes(options.saltLength).toString('base64')
      return hashPassword(user.password, user.salt, options)
        .then(password => {
          user.password = password
          return user
        })
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

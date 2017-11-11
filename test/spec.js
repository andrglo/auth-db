const chai = require('chai')
const expect = chai.expect
chai.should()
const util = require('util')
const randomstring = require('randomstring')

const Redis = require('ioredis')
const redis = new Redis({
  port: process.env.REDIS_PORT || 6379,
  host: process.env.REDIS_HOST || 'redis',
  db: process.env.REDIS_DATABASE || 3
})

const authDb = require('../src')(redis, {
  saltLength: 32,
  iterations: 100000,
  keylen: 512,
  digest: 'sha512'
})

before(function() {
  return redis.flushdb()
})

describe('Users', function() {
  it('should reject due to missing password', function(done) {
    authDb.users.create({
      username: 'Owner'
    }).then(function() {
      done(new Error('Invalid user'))
    }).catch(function(err) {
      err.message.should.equal('Missing password')
      done()
    }).catch(done)
  })
  it('should not update a non existent user', function(done) {
    authDb.users.update({
      username: 'jose'
    }, 'jose').then(function() {
      done(new Error('Invalid update'))
    }).catch(function(err) {
      err.message.should.equal('User not found')
      done()
    }).catch(done)
  })
  it('should not create user Andre, invalid email', function(done) {
    authDb.users.create({
      username: 'Andre',
      password: '12345678',
      firstName: 'André',
      email: 'andre@example.com, andre:example2.com ',
      roles: ['none']
    }).then(function() {
      done(new Error('User created with invalid email'))
    }).catch(function(err) {
      err.message.should.equal('Email andre:example2.com is invalid')
      done()
    }).catch(done)
  })
  it('should create user Andre', function(done) {
    authDb.users.create({
      username: 'Andre',
      password: '12345678',
      firstName: 'André',
      email: 'andre@example.com, andre@example2.com ',
      roles: ['none']
    }).then(function(res) {
      expect(res).equal(true)
      return authDb.users.checkPassword({
        password: '12345678',
        username: 'Andre'
      })
    }).then(res => {
      expect(res).to.equal(true)
      done()
    }).catch(done)
  })
  it('should not create user Andre, already created', function(done) {
    authDb.users.create({
      username: 'ANDRE',
      password: '12345678',
      firstName: 'ARG',
      roles: ['admin']
    }).then(function() {
      done(new Error('Invalid user created'))
    }).catch(function(err) {
      expect(err.message).to.equal('User name already taken')
      done()
    }).catch(done)
  })
  it('Should read field roles as an array', function(done) {
    authDb.users.get('andre').then(function(user) {
      expect(user.roles).to.be.a('array')
      expect(user.roles.length).to.equal(1)
      expect(user.roles).to.eql(['none'])
      expect(user.firstName).to.equal('André')
      done()
    }).catch(done)
  })
  it('Email andre@example.com have been created', function(done) {
    authDb.email.get('andre@example.com').then(function(email) {
      expect(email.username).to.equal('andre')
      done()
    }).catch(done)
  })
  it('Email andre@example2.com have been created', function(done) {
    authDb.email.get('andre@example.com').then(function(email) {
      expect(email.username).to.equal('andre')
      done()
    }).catch(done)
  })
  it('Email andre@example3.com can be added', function(done) {
    authDb.email.add('andre@example3.com', 'andre').then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('Email andre@example.com can have any property', function(done) {
    authDb.email.update({
      username: 'andre',
      verified: '2016-02-19',
      where: 'here'
    }, 'andre@example.com').then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('Email andre@example.com has verified and where properties', function(done) {
    authDb.email.get('andre@example.com').then(function(email) {
      expect(email.verified).to.equal('2016-02-19')
      expect(email.where).to.equal('here')
      done()
    }).catch(done)
  })
  it('Email andre@example.com can have any property modified', function(done) {
    authDb.email.update({
      username: 'andre',
      verified: '2016-02-18',
      where: null
    }, 'andre@example.com').then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('Email andre@example.com cannot be updated without sending the username', function(done) {
    authDb.email.update({verified: '2016-02-19'}, 'andre@example.com').then(function(res) {
      done(new Error('Invalid email update'))
    }).catch((e) => {
      expect(e.message).to.equal('User name is missing or do not match')
      done()
    }).catch(done)
  })
  it('Email andre@example3.com can be removed', function(done) {
    authDb.email.remove('andre@example3.com', 'andre').then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('Email andre@example.com cannot be removed due to verified property', function(done) {
    authDb.email.remove('andre@example.com', 'andre').then(function(res) {
      done(new Error('Invalid email removal'))
    }).catch((e) => {
      expect(e.message).to.equal('Email andre@example.com has been verified and cannot be removed')
      done()
    }).catch(done)
  })
  it('All emails and related data can be fetched', function(done) {
    authDb.users.emails('andre').then(function(emails) {
      expect(emails).to.eql([
        {email: 'andre@example.com', username: 'andre', verified: '2016-02-18', where: ''},
        {email: 'andre@example2.com', username: 'andre'}
      ])
      done()
    }).catch(done)
  })
  it('should update user Andre', function(done) {
    authDb.users.update({
      username: 'ANDRE',
      password: '12345678',
      firstName: 'Heitor',
      lastName: 'Glória',
      roles: ['none', 'other']
    }, 'andre').then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('should not update user Andre email via user api', function(done) {
    authDb.users.update({
      email: 'andre@example3.com'
    }, 'andre').then(function() {
      done(new Error('User cannot have email updated by users api'))
    }).catch(function(err) {
      err.message.should.equal('To update/create/delete a email use email api')
      done()
    }).catch(done)
  })
  it('should read all fields of user Andre', function(done) {
    authDb.users.get('andre').then(function(user) {
      user.should.have.property('username')
      user.should.not.have.property('password')
      user.should.not.have.property('salt')
      user.should.have.property('firstName')
      user.should.have.property('lastName')
      user.username.should.equal('ANDRE')
      user.firstName.should.equal('Heitor')
      user.lastName.should.equal('Glória')
      expect(user.roles).to.be.a('array')
      expect(user.roles.length).to.equal(2)
      expect(user.roles).to.eql(['none', 'other'])
      return authDb.users.checkPassword({
        password: '12345678',
        username: user.username
      })
    }).then(res => {
      expect(res).to.equal(true)
      done()
    }).catch(done)
  })
})

describe('Roles', function() {
  it('should reject due to missing name', function(done) {
    authDb.roles.create({
      field: 'role'
    }).then(function() {
      done(new Error('Invalid role'))
    }).catch(function(err) {
      err.message.should.equal('Role name is missing')
      done()
    }).catch(done)
  })
  it('should not update a non existent role', function(done) {
    authDb.roles.update({
      name: 'role'
    }, 'role').then(function() {
      done(new Error('Invalid update'))
    }).catch(function(err) {
      err.message.should.equal('Role not found')
      done()
    }).catch(done)
  })
  it('should create role without acl', function(done) {
    authDb.roles.create({
      name: 'no acl'
    }).then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('should create role Marketing', function(done) {
    authDb.roles.create({
      name: 'Marketing',
      description: 'Do the marketing',
      acl: ['spec', {
        resource: 'habilis/cadastro',
        methods: ['post', 'put']
      }]
    }).then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('should not recreate role Marketing', function(done) {
    authDb.roles.create({
      name: 'MARKETING',
      description: 'Sell',
      acl: ['any', {
        resource: 'habilis/other',
        methods: ['get']
      }]
    }).then(function() {
      done(new Error('Invalid role created'))
    }).catch(function(err) {
      expect(err.message).to.equal('Role already exists')
      done()
    }).catch(done)
  })
  it('should read all fields of role Marketing', function(done) {
    authDb.roles.get('mArketing').then(function(role) {
      role.should.have.property('name')
      role.description.should.equal('Do the marketing')
      role.name.should.equal('Marketing')
      let resource1, resource2
      role.acl.map(function(aci) {
        if (util.isObject(aci) &&
            aci.resource === 'spec' &&
            aci.methods.length === 1 &&
            aci.methods[0] === '*' &&
            resource1 === void 0) {
          resource1 = true
        }
        if (aci.resource === 'habilis/cadastro' &&
            Array.isArray(aci.methods) &&
            aci.methods.length === 2 &&
            aci.methods.indexOf('POST') !== -1 &&
            aci.methods.indexOf('PUT') !== -1 &&
            resource2 === void 0) {
          resource2 = true
        }
      })
      expect(resource1).to.equal(true)
      expect(resource2).to.equal(true)
      done()
    }).catch(done)
  })
  it('should return an empty object if role does not exist', function(done) {
    authDb.roles.get('tourism').then(function(role) {
      expect(Object.keys(role).length).to.equal(0)
      done()
    }).catch(done)
  })
  it('Marketing should have permission to spec any', function(done) {
    authDb.roles.hasPermission('mArketing', 'spec', 'any').then(function(allowed) {
      allowed.should.equal(true)
      done()
    }).catch(done)
  })
  it('Marketing should have permission to spec', function(done) {
    authDb.roles.hasPermission('mArketing', 'spec').then(function(allowed) {
      allowed.should.equal(true)
      done()
    }).catch(done)
  })
  it('Marketing should not have permission to spec2', function(done) {
    authDb.roles.hasPermission('mArketing', 'spec2').then(function(allowed) {
      allowed.should.equal(false)
      done()
    }).catch(done)
  })
  it('Marketing should not have permission to habilis/cadastro get', function(done) {
    authDb.roles.hasPermission('mArketing', 'habilis/cadastro', 'get').then(function(allowed) {
      allowed.should.equal(false)
      done()
    }).catch(done)
  })
  it('nor to habilis/cadastro', function(done) {
    authDb.roles.hasPermission('mArketing', 'habilis/cadastro').then(function(allowed) {
      allowed.should.equal(false)
      done()
    }).catch(done)
  })
  it('but do to habilis/cadastro post', function(done) {
    authDb.roles.hasPermission('mArketing', 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(true)
      done()
    }).catch(done)
  })
  it('Role mArketing in a array should have permission to habilis/cadastro post', function(done) {
    authDb.roles.hasPermission(['a', 'b', 'c', 'mArketing', 'd'], 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(true)
      done()
    }).catch(done)
  })
  it('Role mArketing in a array should have permission to habilis/cadastro post - last position', function(done) {
    authDb.roles.hasPermission(['a', 'b', 'c', 'mArketing'], 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(true)
      done()
    }).catch(done)
  })
  it('Role mArketing if not in the array should should not have permission to habilis/cadastro post', function(done) {
    authDb.roles.hasPermission(['a', 'b', 'c'], 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(false)
      done()
    }).catch(done)
  })
  it('Role undefined should be rejected', function(done) {
    authDb.roles.hasPermission([void 0], 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(false)
      done()
    }).catch(done)
  })
  it('should update role Marketing', function(done) {
    authDb.roles.update({
      name: 'MARKETING',
      location: 'unknown',
      acl: [{
        resource: 'token',
        methods: 'get'
      }, {
        resource: 'habilis/cadastro',
        methods: ['post', 'update']
      }]
    }, 'marketing').then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('lets check all fields of role Marketing', function(done) {
    authDb.roles.get('mArketing').then(function(role) {
      role.should.have.property('name')
      role.should.have.property('description')
      role.should.have.property('location')
      role.name.should.equal('MARKETING')
      role.description.should.equal('Do the marketing')
      role.location.should.equal('unknown')
      let resource1
      let resource2
      role.acl.map(function(aci) {
        if (aci.resource === 'token' &&
            Array.isArray(aci.methods) &&
            aci.methods[0] === 'GET' &&
            resource1 === void 0) {
          resource1 = true
        }
        if (aci.resource === 'habilis/cadastro' &&
            Array.isArray(aci.methods) &&
            aci.methods.length === 2 &&
            aci.methods.indexOf('POST') !== -1 &&
            aci.methods.indexOf('UPDATE') !== -1 &&
            resource2 === void 0) {
          resource2 = true
        }
      })
      expect(resource1).to.equal(true)
      expect(resource2).to.equal(true)
      done()
    }).catch(done)
  })
  it('lets list all roles beginning with m', function(done) {
    authDb.roles.list('m').then(function(roles) {
      expect(roles).to.eql(['marketing'])
      done()
    }).catch(done)
  })
})

describe('Sessions', function() {
  it('should return an empty session', function(done) {
    authDb.sessions.get().then(function(res) {
      expect(res).to.deep.equal({})
      done()
    }).catch(done)
  })
  let session
  it('should create a new session valid for 1 second', function(done) {
    authDb.sessions.create('andre', {
      username: 'andre'
    }, 1).then(function(res) {
      expect(res).to.be.a('string')
      session = res
      setTimeout(function() {
        done()
      }, 500)
    }).catch(done)
  })
  it('should exists yet', function(done) {
    authDb.sessions.get('andre', session).then(function(res) {
      expect(res.username === 'andre').to.equal(true)
      setTimeout(function() {
        done()
      }, 500)
    }).catch(done)
  })
  it('now should have gone', function(done) {
    authDb.sessions.get('andre', session).then(function(res) {
      expect(res).to.deep.equal({})
      done()
    }).catch(done)
  })
  it('should create a new session valid for 1 minute', function(done) {
    authDb.sessions.create('andre', {
      username: 'andre'
    }, 60).then(function(res) {
      expect(res).to.be.a('string')
      session = res
      done()
    }).catch(done)
  })
  it('ok, created', function(done) {
    authDb.sessions.get('andre', session).then(function(res) {
      expect(res.username === 'andre').to.equal(true)
      done()
    }).catch(done)
  })
  it('but if I delete it', function(done) {
    authDb.sessions.destroy('andre', session).then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('now should have gone', function(done) {
    authDb.sessions.get('andre', session).then(function(res) {
      expect(res).to.deep.equal({})
      done()
    }).catch(done)
  })
  const andreSessions = []
  const johnSessions = []
  it('should create 2 new sessions for andre', function(done) {
    authDb.sessions.create('andre', {
      username: 'andre'
    }, 9999).then(function(res) {
      expect(res).to.be.a('string')
      andreSessions.push(res)
      return authDb.sessions.create('andre', {
        username: 'andre'
      }, 9999)
    }).then(function(res) {
      expect(res).to.be.a('string')
      andreSessions.push(res)
      done()
    }).catch(done)
  })
  it('should create 1 new sessions for john', function(done) {
    authDb.sessions.create('john', {
      username: 'john'
    }, 9999).then(function(res) {
      expect(res).to.be.a('string')
      johnSessions.push(res)
      done()
    }).catch(done)
  })
  it('lets destroy all sessions for andre', function(done) {
    authDb.sessions.reset('andre').then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(done)
  })
  it('no session 0 for andre now', function(done) {
    authDb.sessions.get('andre', andreSessions[0]).then(function(res) {
      expect(res).to.deep.equal({})
      done()
    }).catch(done)
  })
  it('no session 1 for andre now', function(done) {
    authDb.sessions.get('andre', andreSessions[1]).then(function(res) {
      expect(res).to.deep.equal({})
      done()
    }).catch(done)
  })
  it('john should exist yet', function(done) {
    authDb.sessions.get('john', johnSessions[0]).then(function(res) {
      expect(res.username === 'john').to.equal(true)
      done()
    }).catch(done)
  })
})

describe('Permission check benchmark', function() {
  it('should save a random string 10000 times', function(done) {
    let acl = []
    for (let i = 0; i < 10000; i++) {
      acl.push({
        resource: randomstring.generate(100),
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'ANY_METHOD_ANY_LENGTH']
      })
    }
    acl.push({
      resource: 'resource'
    })
    authDb.roles.create({
      name: 'teste de benchmark',
      description: 'Do the benchmark',
      acl: acl
    }).then(function(res) {
      expect(res).equal(true)
      done()
    }).catch(function(err) {
      done(err)
    })
  })
  it('should test 1000 times and have access permission', function(done) {
    let initial = new Date()
    let promises = Promise.resolve()
    for (let i = 0; i < 1000; i++) {
      promises = promises.then(function() {
        return authDb.roles.hasPermission('teste de benchmark', 'resource').then(function(allowed) {
          allowed.should.equal(true)
        })
      })
    }
    promises.then(function() {
      let final = new Date()
      expect(final.getTime() - initial.getTime()).to.be.below(600)
      done()
    }).catch(done)
  })
  it('lets list all roles', function(done) {
    authDb.roles.list().then(function(roles) {
      expect(roles.length).to.equal(3)
      expect(roles).to.include('no acl')
      expect(roles).to.include('marketing')
      expect(roles).to.include('teste de benchmark')
      done()
    }).catch(done)
  })
})

after(function() {
  return redis.quit()
})

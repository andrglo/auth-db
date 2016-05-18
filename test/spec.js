'use strict';

var chai = require('chai');
var expect = chai.expect;
chai.should();
var util = require('util');
var randomstring = require('randomstring');

var Redis = require('ioredis');
var redis = new Redis({
  port: process.env.REDIS_PORT || 6379,
  host: process.env.REDIS_HOST || '127.0.0.1',
  db: process.env.REDIS_DATABASE || 0
});

var authDb = require('../src')(redis, {
  saltLength: 32,
  iterations: 100000,
  keylen: 512,
  digest: 'sha512'
});

var log = console.log;

before(function() {
  return redis.flushdb();
});

describe('Users', function() {
  it('should reject due to missing password', function(done) {
    authDb.users.create({
      username: 'Owner'
    }).then(function() {
      done(new Error('Invalid user'));
    }).catch(function(err) {
      err.message.should.equal('Missing password');
      done();
    }).catch(done);
  });
  it('should not update a non existent user', function(done) {
    authDb.users.update({
      username: 'jose'
    }, 'jose').then(function() {
      done(new Error('Invalid update'));
    }).catch(function(err) {
      err.message.should.equal('User not found');
      done();
    }).catch(done);
  });
  it('should create user Andre', function(done) {
    authDb.users.create({
      username: 'Andre',
      password: '12345678',
      firstName: 'André',
      email: 'andre@example.com, andre@example2.com ',
      roles: ['none']
    }).then(function(res) {
      res.should.be.true;
      return authDb.users.checkPassword({
        password: '12345678',
        username: 'Andre'
      });
    }).then(res => {
      expect(res).to.equal(true);
      done();
    }).catch(done);
  });
  it('should not create user Andre, already created', function(done) {
    authDb.users.create({
      username: 'ANDRE',
      password: '12345678',
      firstName: 'ARG',
      roles: ['admin']
    }).then(function() {
      done(new Error('Invalid user created'));
    }).catch(function(err) {
      expect(err.message).to.equal('User name already taken');
      done();
    }).catch(done);
  });
  it('Should read field roles as an array', function(done) {
    authDb.users.get('andre').then(function(user) {
      expect(user.roles).to.be.a('array');
      expect(user.roles.length).to.equal(1);
      expect(user.roles).to.eql(['none']);
      expect(user.firstName).to.equal('André');
      done();
    }).catch(done);
  });
  it('Email andre@example.com have been created', function(done) {
    authDb.email.get('andre@example.com').then(function(email) {
      expect(email.username).to.equal('andre');
      done();
    }).catch(done);
  });
  it('Email andre@example2.com have been created', function(done) {
    authDb.email.get('andre@example.com').then(function(email) {
      expect(email.username).to.equal('andre');
      done();
    }).catch(done);
  });
  it('Email andre@example.com can have any property', function(done) {
    authDb.email.update({
      username: 'andre',
      verified: '2016-02-18'
    }, 'andre@example.com').then(function(res) {
      res.should.be.true;
      done();
    }).catch(done);
  });
  it('Email andre@example.com has verified date property', function(done) {
    authDb.email.get('andre@example.com').then(function(email) {
      expect(email.verified).to.equal('2016-02-18');
      done();
    }).catch(done);
  });
  it('Email andre@example.com cannot be updated without sending the username', function(done) {
    authDb.email.update({ verified: '2016-02-19' }, 'andre@example.com').then(function(res) {
      done(new Error('Invalid email update'));
    }).catch((e) => {
      expect(e.message).to.equal('User name is missing or do not match');
      done();
    });
  });
  it('All emails and related data can be fetched', function(done) {
    authDb.users.emails('andre').then(function(emails) {
      expect(emails).to.eql([
        { email: 'andre@example.com', username: 'andre', verified: '2016-02-18' },
        { email: 'andre@example2.com', username: 'andre' }
      ]);
      done();
    }).catch(done);
  });
  it('should update user Andre', function(done) {
    authDb.users.update({
      username: 'ANDRE',
      password: '12345678',
      firstName: 'Heitor',
      lastName: 'Glória',
      roles: ['none', 'other']
    }, 'andre').then(function(res) {
      res.should.be.true;
      done();
    }).catch(done);
  });
  it('should read all fields of user Andre', function(done) {
    authDb.users.get('andre').then(function(user) {
      user.should.have.property('username');
      user.should.not.have.property('password');
      user.should.not.have.property('salt');
      user.should.have.property('firstName');
      user.should.have.property('lastName');
      user.username.should.equal('ANDRE');
      user.firstName.should.equal('Heitor');
      user.lastName.should.equal('Glória');
      expect(user.roles).to.be.a('array');
      expect(user.roles.length).to.equal(2);
      expect(user.roles).to.eql(['none', 'other']);
      return authDb.users.checkPassword({
        password: '12345678',
        username: user.username
      });
    }).then(res => {
      expect(res).to.equal(true);
      done();
    }).catch(done);
  });
});

describe('Roles', function() {
  it('should reject due to missing name', function(done) {
    authDb.roles.create({
      field: 'role'
    }).then(function() {
      done(new Error('Invalid role'))
    }).catch(function(err) {
      err.message.should.equal('Role name is missing');
      done();
    }).catch(done);
  });
  it('should not update a non existent role', function(done) {
    authDb.roles.update({
      name: 'role'
    }, 'role').then(function() {
      done(new Error('Invalid update'))
    }).catch(function(err) {
      err.message.should.equal('Role not found');
      done();
    }).catch(done);
  });
  it('should create role without acl', function(done) {
    authDb.roles.create({
      name: 'no acl'
    }).then(function(res) {
      res.should.be.true;
      done();
    }).catch(done);
  });
  it('should create role Marketing', function(done) {
    authDb.roles.create({
      name: 'Marketing',
      description: 'Do the marketing',
      acl: ['spec', {
        resource: 'habilis/cadastro',
        methods: ['post', 'put']
      }]
    }).then(function(res) {
      res.should.be.true;
      done();
    }).catch(done);
  });
  it('should not recreate role Marketing', function(done) {
    authDb.roles.create({
      name: 'MARKETING',
      description: 'Sell',
      acl: ['any', {
        resource: 'habilis/other',
        methods: ['get']
      }]
    }).then(function() {
      done(new Error('Invalid role created'));
    }).catch(function(err) {
      expect(err.message).to.equal('Role already exists');
      done();
    }).catch(done);
  });
  it('should read all fields of role Marketing', function(done) {
    authDb.roles.get('mArketing').then(function(role) {
      role.should.have.property('name');
      role.description.should.equal('Do the marketing');
      role.name.should.equal('Marketing');
      let resource1, resource2;
      role.acl.map(function(aci) {
        if (util.isObject(aci) &&
          aci.resource === 'spec' &&
          aci.methods.length === 1 &&
          aci.methods[0] === '*' &&
          resource1 === void 0) {
          resource1 = true;
        }
        if (aci.resource === 'habilis/cadastro' &&
          Array.isArray(aci.methods) &&
          aci.methods.length === 2 &&
          aci.methods.indexOf('POST') !== -1 &&
          aci.methods.indexOf('PUT') !== -1 &&
          resource2 === void 0) {
          resource2 = true;
        }
      });
      expect(resource1).to.equal(true);
      expect(resource2).to.equal(true);
      done();
    }).catch(done);
  });
  it('Marketing should have permission to spec any', function(done) {
    authDb.roles.hasPermission('mArketing', 'spec', 'any').then(function(allowed) {
      allowed.should.equal(true);
      done();
    }).catch(done);
  });
  it('Marketing should have permission to spec', function(done) {
    authDb.roles.hasPermission('mArketing', 'spec').then(function(allowed) {
      allowed.should.equal(true);
      done();
    }).catch(done);
  });
  it('Marketing should not have permission to spec2', function(done) {
    authDb.roles.hasPermission('mArketing', 'spec2').then(function(allowed) {
      allowed.should.equal(false);
      done();
    }).catch(done);
  });
  it('Marketing should not have permission to habilis/cadastro get', function(done) {
    authDb.roles.hasPermission('mArketing', 'habilis/cadastro', 'get').then(function(allowed) {
      allowed.should.equal(false);
      done();
    }).catch(done);
  });
  it('nor to habilis/cadastro', function(done) {
    authDb.roles.hasPermission('mArketing', 'habilis/cadastro').then(function(allowed) {
      allowed.should.equal(false);
      done();
    }).catch(done);
  });
  it('but do to habilis/cadastro post', function(done) {
    authDb.roles.hasPermission('mArketing', 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(true);
      done();
    }).catch(done);
  });
  it('Role mArketing in a array should have permission to habilis/cadastro post', function(done) {
    authDb.roles.hasPermission(['a', 'b', 'c', 'mArketing', 'd'], 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(true);
      done();
    }).catch(done);
  });
  it('Role mArketing in a array should have permission to habilis/cadastro post - last position', function(done) {
    authDb.roles.hasPermission(['a', 'b', 'c', 'mArketing'], 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(true);
      done();
    }).catch(done);
  });
  it('Role mArketing if not in the array should should not have permission to habilis/cadastro post', function(done) {
    authDb.roles.hasPermission(['a', 'b', 'c'], 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(false);
      done();
    }).catch(done);
  });
  it('Role undefined should be rejected', function(done) {
    authDb.roles.hasPermission([void 0], 'habilis/cadastro', 'post').then(function(allowed) {
      allowed.should.equal(false);
      done();
    }).catch(done);
  });
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
      res.should.be.true;
      done();
    }).catch(done);
  });
  it('lets check all fields of role Marketing', function(done) {
    authDb.roles.get('mArketing').then(function(role) {
      role.should.have.property('name');
      role.should.have.property('description');
      role.should.have.property('location');
      role.name.should.equal('MARKETING');
      role.description.should.equal('Do the marketing');
      role.location.should.equal('unknown');
      let resource1, resource2;
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
      });
      expect(resource1).to.equal(true);
      expect(resource2).to.equal(true);
      done();
    }).catch(done);
  });
});

describe('Sessions', function() {
  it('should return an empty session', function(done) {
    authDb.sessions.get('1').then(function(res) {
      expect(res).to.deep.equal({});
      done()
    }).catch(done)
  });
  var session;
  it('should create a new session valid for 1 second', function(done) {
    authDb.sessions.create(1, {
      username: 'andre'
    }).then(function(res) {
      expect(res).to.be.a('string');
      session = res;
      setTimeout(function() {
        done();
      }, 500);
    }).catch(done);
  });
  it('should exists yet', function(done) {
    authDb.sessions.get(session).then(function(res) {
      expect(res.username === 'andre').to.equal(true);
      setTimeout(function() {
        done()
      }, 500);
    }).catch(done);
  });
  it('now should have gone', function(done) {
    authDb.sessions.get(session).then(function(res) {
      expect(res).to.deep.equal({});
      done()
    }).catch(done);
  });
  it('should create a new session valid for 1 minute', function(done) {
    authDb.sessions.create(60, {
      username: 'andre'
    }).then(function(res) {
      expect(res).to.be.a('string');
      session = res;
      done();
    }).catch(done);
  });
  it('ok, created', function(done) {
    authDb.sessions.get(session).then(function(res) {
      expect(res.username === 'andre').to.equal(true);
      done();
    }).catch(done);
  });
  it('but if I delete it', function(done) {
    authDb.sessions.destroy(session).then(function(res) {
      res.should.be.true;
      done();
    }).catch(done);
  });
  it('now should have gone', function(done) {
    authDb.sessions.get(session).then(function(res) {
      expect(res).to.deep.equal({});
      done()
    }).catch(done);
  });
});

describe('Permission check benchmark', function() {
  it('should save a random string 10000 times', function(done) {
    let acl = [];
    for (var i = 0; i < 10000; i++) {
      acl.push({
        resource: randomstring.generate(100),
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'ANY_METHOD_ANY_LENGTH']
      });
    }
    acl.push({
      resource: 'resource'
    });
    authDb.roles.create({
      name: 'teste de benchmark',
      description: 'Do the benchmark',
      acl: acl
    }).then(function(res) {
      res.should.be.true;
      done();
    }).catch(function(err) {
      done(err);
    });
  });
  it('should test 1000 times and have access permission', function(done) {
    let initial = new Date();
    let promises = Promise.resolve();
    for (var i = 0; i < 1000; i++) {
      promises = promises.then(function() {
        return authDb.roles.hasPermission('teste de benchmark', 'resource').then(function(allowed) {
          allowed.should.equal(true);
        });
      });
    }
    promises.then(function() {
      let final = new Date();
      expect(final.getTime() - initial.getTime()).to.be.below(600);
      done();
    }).catch(done);
  });
});

after(function() {
  return redis.quit();
});

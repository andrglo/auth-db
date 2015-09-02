'use strict';

var chai = require('chai');
var expect = chai.expect;
chai.should();
var _ = require('lodash');
var gutil = require('gulp-util');
var randomstring = require('randomstring');

var log = gutil.log;

module.exports = function(options) {

  var db;
  before(function() {
    db = options.db;
  });

  describe('Users', function() {
    it('should reject due to missing password', function(done) {
      db.users.create({
        username: 'Owner'
      }).then(function() {
        done(new Error('Invalid user'))
      }).catch(function(err) {
        err.message.should.equal('missing password');
        done();
      });
    });
    it('should not update a non existent user', function(done) {
      db.users.update({
        username: 'jose'
      }, 'jose').then(function() {
        done(new Error('Invalid update'))
      }).catch(function(err) {
        err.message.should.equal('user not found');
        done();
      });
    });
    it('should create user Andre', function(done) {
      db.users.create({
        username: 'Andre',
        password: '12345678',
        firstName: 'André'
      }).then(function(res) {
        res.should.be.true;
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('should update user Andre', function(done) {
      db.users.update({
        username: 'ANDRE',
        password: '12345678',
        firstName: 'Heitor',
        lastName: 'Glória'
      }, 'andre').then(function(res) {
        res.should.be.true;
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('should read all fields of user Andre', function(done) {
      db.users.get('andre').then(function(user) {
        user.should.have.property('username');
        user.should.have.property('password');
        user.should.have.property('salt');
        user.should.have.property('firstName');
        user.should.have.property('lastName');
        user.should.have.property('salt');
        user.username.should.equal('ANDRE');
        user.password.should.not.equal('12345678');
        expect(db.users.checkPassword('12345678', user)).to.equal(true);
        user.firstName.should.equal('Heitor');
        user.lastName.should.equal('Glória');
        done();
      }).catch(function(err) {
        done(err);
      });
    });
  });

  describe('Roles', function() {
    it('should reject due to missing name', function(done) {
      db.roles.create({
        field: 'role'
      }).then(function() {
        done(new Error('Invalid role'))
      }).catch(function(err) {
        err.message.should.equal('missing name');
        done();
      });
    });
    it('should not update a non existent role', function(done) {
      db.roles.update({
        name: 'role'
      }, 'role').then(function() {
        done(new Error('Invalid update'))
      }).catch(function(err) {
        err.message.should.equal('role not found');
        done();
      });
    });
    it('should create role without acl', function(done) {
      db.roles.create({
        name: 'no acl'
      }).then(function(res) {
        res.should.be.true;
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('should create role Marketing', function(done) {
      db.roles.create({
        name: 'Marketing',
        description: 'Do the marketing',
        acl: ['spec', {
          resource: 'habilis/cadastro',
          methods: ['post', 'put']
        }]
      }).then(function(res) {
        res.should.be.true;
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('should read all fields of role Marketing', function(done) {
      db.roles.get('mArketing').then(function(role) {
        role.should.have.property('name');
        role.should.have.property('description');
        role.name.should.equal('Marketing');
        let resource1, resource2;
        role.acl.map(function(aci) {
          if (_.isObject(aci) &&
            aci.resource === 'spec' &&
            aci.methods.length === 1 &&
            aci.methods[0] === '*' &&
            resource1 === void 0) {
            resource1 = true;
          }
          if (aci.resource === 'habilis/cadastro' &&
            _.isArray(aci.methods) &&
            aci.methods.length === 2 &&
            aci.methods.indexOf('POST') !== -1 &&
            aci.methods.indexOf('PUT') !== -1 &&   //todo fix tests bellow
            resource2 === void 0) {//todo implement role hasPermissions
            resource2 = true;
          }
        });
        expect(resource1).to.equal(true);
        expect(resource2).to.equal(true);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('Marketing should have permission to spec any', function(done) {
      db.roles.hasPermission('mArketing', 'spec', 'any').then(function(allowed) {
        allowed.should.equal(true);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('Marketing should have permission to spec', function(done) {
      db.roles.hasPermission('mArketing', 'spec').then(function(allowed) {
        allowed.should.equal(true);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('Marketing should not have permission to spec2', function(done) {
      db.roles.hasPermission('mArketing', 'spec2').then(function(allowed) {
        allowed.should.equal(false);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('Marketing should not have permission to habilis/cadastro get', function(done) {
      db.roles.hasPermission('mArketing', 'habilis/cadastro', 'get').then(function(allowed) {
        allowed.should.equal(false);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('nor to habilis/cadastro', function(done) {
      db.roles.hasPermission('mArketing', 'habilis/cadastro').then(function(allowed) {
        allowed.should.equal(false);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('but do to habilis/cadastro post', function(done) {
      db.roles.hasPermission('mArketing', 'habilis/cadastro', 'post').then(function(allowed) {
        allowed.should.equal(true);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('should update role Marketing', function(done) {
      db.roles.update({
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
      }).catch(function(err) {
        done(err);
      });
    });
    it('lets check all fields of role Marketing', function(done) {
      db.roles.get('mArketing').then(function(role) {
        role.should.have.property('name');
        role.should.have.property('description');
        role.should.have.property('location');
        role.name.should.equal('MARKETING');
        role.description.should.equal('Do the marketing');
        role.location.should.equal('unknown');
        let resource1, resource2;
        role.acl.map(function(aci) {
          if (aci.resource === 'token' &&
            _.isArray(aci.methods) &&
            aci.methods[0] === 'GET' &&
            resource1 === void 0) {
            resource1 = true
          }
          if (aci.resource === 'habilis/cadastro' &&
            _.isArray(aci.methods) &&
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
      }).catch(function(err) {
        done(err);
      });
    });
  });

  describe('Sessions', function() {
    it('should return an empty session', function(done) {
      db.sessions.get('1').then(function(res) {
        expect(_.isEmpty(res)).to.equal(true);
        done()
      }).catch(function(err) {
        done(err);
      })
    });
    var session;
    it('should create a new session valid for 1 second', function(done) {
      db.sessions.create(1, {
        username: 'andre'
      }).then(function(res) {
        expect(res).to.be.a('string');
        session = res;
        setTimeout(function() {
          done();
        }, 500);
      }).catch(function(err) {
        done(err);
      });
    });
    it('should exists yet', function(done) {
      db.sessions.get(session).then(function(res) {
        expect(res.username === 'andre').to.equal(true);
        setTimeout(function() {
          done()
        }, 500);
      }).catch(function(err) {
        done(err);
      });
    });
    it('now should have gone', function(done) {
      db.sessions.get(session).then(function(res) {
        expect(_.isEmpty(res)).to.equal(true);
        done()
      }).catch(function(err) {
        done(err);
      });
    });
    it('should create a new session valid for 1 minute', function(done) {
      db.sessions.create(60, {
        username: 'andre'
      }).then(function(res) {
        expect(res).to.be.a('string');
        session = res;
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('ok, created', function(done) {
      db.sessions.get(session).then(function(res) {
        expect(res.username === 'andre').to.equal(true);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('but if I delete it', function(done) {
      db.sessions.destroy(session).then(function(res) {
        res.should.be.true;
        done();
      }).catch(function(err) {
        done(err);
      });
    });
    it('now should have gone', function(done) {
      db.sessions.get(session).then(function(res) {
        expect(_.isEmpty(res)).to.equal(true);
        done()
      }).catch(function(err) {
        done(err);
      });
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
      db.roles.create({
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
          return db.roles.hasPermission('teste de benchmark', 'resource').then(function(allowed) {
            allowed.should.equal(true);
          });
        });
      }
      promises.then(function() {
        let final = new Date();
        expect(final.getTime() - initial.getTime()).to.be.below(500);
        done();
      }).catch(function(err) {
        done(err);
      });
    });
  });

};

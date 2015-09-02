var gutil = require('gulp-util');

var Redis = require('ioredis');
var redis = new Redis({
  port: process.env.REDIS_PORT || 6379,
  host: process.env.REDIS_HOST || '127.0.0.1',
  db: process.env.REDIS_DATABASE || 11
});

var authDb = require('../src');
var spec = require('./spec');

var log = gutil.log;

describe('ioredis', function() {
  var options = {};
  var duration;
  before(function(done) {
    redis.flushdb()
      .then(function() {
        log('db flushed');
        options.db = authDb(redis);
        duration = process.hrtime();
        done();
      })
      .catch(done);
  });
  spec(options);
  after(function() {
    duration = process.hrtime(duration);
    redis.disconnect();
    log('ioredis finished');
  });
});

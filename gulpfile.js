const path = require('path')
const gulp = require('gulp')
const eslint = require('gulp-eslint')
const mocha = require('gulp-mocha')
const nsp = require('gulp-nsp')

gulp.task('static', function() {
  return gulp.src('src/**/*.js')
    .pipe(eslint())
    .pipe(eslint.format())
    .pipe(eslint.failAfterError())
})

gulp.task('nsp', function(cb) {
  nsp({package: path.join(__dirname, 'package.json')}, cb)
})

gulp.task('test', function(cb) {
  let error
  gulp.src('test/spec.js')
    .pipe(mocha({reporter: 'spec', bail: true, timeout: 15000}))
    .on('error', function(e) {
      error = e
      cb(error)
    })
    .on('end', function() {
      if (!error) {
        cb()
      }
    })
})

gulp.task('prepublish', ['nsp'])
gulp.task('default', ['static', 'test'])

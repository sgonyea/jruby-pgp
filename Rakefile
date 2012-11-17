require 'bundler/gem_tasks'
require 'rake/javaextensiontask'

require 'rspec/core/rake_task'

Rake::JavaExtensionTask.new('jruby-pgp') do |ext|
  jruby_home = RbConfig::CONFIG['prefix']
  jars = ["#{jruby_home}/lib/jruby.jar"] + FileList['lib/pgp/jars/*.jar']

  ext.ext_dir   = 'ext'
  ext.lib_dir   = 'lib/pgp'
  ext.classpath = jars.map { |x| File.expand_path x }.join ':'
end

RSpec::Core::RakeTask.new

RSpec::Core::RakeTask.new(:rcov) do |task|
    task.rcov = true
end

task :default => %w(compile spec)

task :build => :compile
task :spec  => :compile

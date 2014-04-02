# encoding: utf-8

require 'rubygems'
require 'bundler'
begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts 'Run `bundle install` to install missing gems'
  exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://guides.rubygems.org/specification-reference/ for more options
  gem.name = 'has_secure_attribute'
  gem.homepage = 'http://github.com/jordansexton/has_secure_attribute'
  gem.license = 'MIT'
  gem.summary = 'ActiveRecord extensions for securely hashing passwords and other attributes.'
  gem.description = 'ActiveRecord extensions for securely hashing passwords and other attributes.'
  gem.email = 'jordan@jordansexton.com'
  gem.authors = ['Jordan Sexton']
  # dependencies defined in Gemfile
end
# Jeweler::RubygemsDotOrgTasks.new

require 'rspec/core'
require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.pattern = FileList['spec/**/*_spec.rb']
end

desc 'Code coverage detail'
task :simplecov do
  ENV['COVERAGE'] = 'true'
  Rake::Task['spec'].execute
end

task :default => :spec

require 'rdoc/task'
Rake::RDocTask.new do |rdoc|
  version = File.exist?('VERSION') ? File.read('VERSION') : ''

  rdoc.rdoc_dir = 'rdoc'
  rdoc.title = "has_secure_attribute #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

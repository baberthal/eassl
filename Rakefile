require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'rubocop/rake_task'
require 'ruby-lint/rake_task'

RSpec::Core::RakeTask.new(:spec)

RuboCop::RakeTask.new(:rubocop) do |t|
  t.patterns = ['{lib,spec}/**/*.rb']
  t.formatters = %w(progress fuubar)
  t.fail_on_error = false
end

RubyLint::RakeTask.new do |t|
  t.name = :lint
  t.files = ['lib/']
end

task default: :spec

source 'https://rubygems.org'

# Specify your gem's dependencies in eassl.gemspec
gemspec

group :development, :test do
  gem 'guard-rspec', require: false
  gem 'rubocop', require: false
  gem 'rubocop-rspec', require: false
  gem 'rb-fsevent', require: false if RUBY_PLATFORM =~ /darwin/i
  gem 'pry', require: false
  gem 'pry-theme', require: false
  gem 'colorize', require: false
  gem 'reek', require: false
  gem 'overcommit'
  gem 'ruby-lint', github: 'baberthal/ruby-lint'
end

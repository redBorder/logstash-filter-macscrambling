Gem::Specification.new do |s|
  s.name = 'logstash-filter-macscrambling'
  s.version = '1.0.7'
  s.licenses = ['Apache License (2.0)']
  s.summary = "This filter classifies the ip analyzed in the event and categorizes it according to its origin."
  s.description = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["redBorder"]
  s.email = 'systems@redborder.com'
  s.homepage = "https://www.redborder.com"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency 'pg_jruby', '~>0.17.1'
  s.add_runtime_dependency 'dalli'
  
  s.add_development_dependency 'logstash-devutils'
end

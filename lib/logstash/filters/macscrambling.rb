# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"

require 'pg'
require 'json'
require 'iso8601'
require 'fileutils'
require 'aws'
require 'zk'
require 'socket'


class LogStash::Filters::MacScrambling < LogStash::Filters::Base

  db_name = "development"  
  config_name = "macscrambling"

  public
  def register
    @scrambles = nil
    begin
      
      # PG connection
      db_config = YAML.load_file("/opt/rb/var/www/rb-rails/config/database.yml")
      db =  PG.connect(dbname: db_config[db_name]["database"], user: db_config[db_name]["username"], password: db_config[db_name]["password"], port: db_config[db_name]["port"], host: db_config[db_name]["host"])
        
      scrambles = []
      # Get sensors info from PG
      db.exec("SELECT uuid, property FROM sensors WHERE domain_type=6;") do |result|
        result.each do |row|
          scrambles = row
        end
      end
      puts scrambles
      
    rescue  PG::Error =>e
      @scrambles = nil
      puts e.message

    ensure
      puts "Connection closed"
      db.close if db

    end
  end

  def filter(event)
    
  end  # def filter
end    # class Logstash::Filter::MacScrambling

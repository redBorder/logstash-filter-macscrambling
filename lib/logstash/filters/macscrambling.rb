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

  config_name "macscrambling"

  public
  def register
    @db_name = "development"  
    @ts_start = Time.now
    @scrambles = nil

    update_salt
  end

  def filter(event)
    ts_end = Time.now - @ts_start
    if ts_end >= 60 then
      update_salt
    end
    
    #TODO

    
  end  # def filter

  def update_salt
    begin
        
      # PG connection
      db_config = YAML.load_file("/opt/rb/var/www/rb-rails/config/database.yml")
      db =  PG.connect(dbname: db_config[@db_name]["database"], user: db_config[@db_name]["username"], password: db_config[@db_name]["password"], port: db_config[@db_name]["port"], host: db_config[@db_name]["host"])
        
      @scrambles = []

      # Get sensor info from PG
      db.exec("SELECT uuid, property FROM sensors WHERE domain_type=6;") do |result|
        result.each do |row|
          @scrambles << row
        end
      ends
    rescue  PG::Error =>e
      @scrambles = nil
      puts "[MacScrambling] " + e.message
    
    ensure
      db.close if db
    end
  end  # def update_salt

end    # class Logstash::Filter::MacScrambling

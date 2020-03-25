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
    @scrambles = Hash.new
    @mac_prefix = 123 #TODO

    update_salt
  end

  def filter(event)
    ts_end = Time.now - @ts_start
    if ts_end >= 60 then
      update_salt
      @ts_start = Time.now
    end
    
    mac = event.get("client_mac")
    spUUID = event.get("service_provider_uuid")

    begin
      scramble = @scrambles[spUUID.to_s]["mac_hashing_salt"]
      
      if scramble and mac then     
        # Decode Hexadecimal value, scramble and write to the mac format
        decoded_mac = [mac.gsub(":","").to_s].pack('H*')
        decoded_mac_screamble = scramble_mac(decoded_mac)
        decoded_mac_screamble_to_mac = to_mac(decoded_mac_screamble, ":")

        message.put("client_mac",decoded_mac_screamble_to_mac)
      end
    rescue
      @scrambles = Hash.new
      puts "GeneralSecurityException"
    end
    
  end  # def filter

  def scramble_mac
    #TODO - PKCS5S2ParametersGenerator
  end

  def to_mac(value, separator)
    #TODO - StringBuilder

  end

  # Connect to Postgresql DB to get information from sensors
  def update_salt
    begin
        
      # PG connection
      db_config = YAML.load_file("/opt/rb/var/www/rb-rails/config/database.yml")
      db =  PG.connect(dbname: db_config[@db_name]["database"], user: db_config[@db_name]["username"], password: db_config[@db_name]["password"], port: db_config[@db_name]["port"], host: db_config[@db_name]["host"])
        
      @scrambles = Hash.new

      # Get sensor info from PG
      db.exec("SELECT uuid, property FROM sensors WHERE domain_type=6;") do |result|
        result.each do |row|
          
          #"Property" field has a json embessed
          json_content = JSON.parse(row["property"])

          # Decoding from Hexadecimal to string
          salt = [json_content["mac_hashing_salt"].to_s].pack('H*')
          
          @scrambles[row["uuid"].to_s] = Hash.new
          @scrambles[row["uuid"].to_s]["mac_hashing_salt"] = salt  

          if mac_prefix and mac_prefix.to_s.strip.empty?
            @scrambles[row["uuid"].to_s]["mac_prefix"] = @mac_prefix.bytes.to_a   #to Byte array
        end
      end

    rescue  PG::Error =>e
      @scrambles = Hash.new
      puts "[MacScrambling] " + e.message
    
    ensure
      db.close if db
    end
  end  # def update_salt

end    # class Logstash::Filter::MacScrambling

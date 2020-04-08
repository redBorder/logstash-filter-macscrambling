# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"

require 'pg'
require 'json'
require 'yaml'
require 'fileutils'
require 'socket'
require 'openssl'


class LogStash::Filters::Macscrambling < LogStash::Filters::Base
  
  config_name "macscrambling"
  
  public
  def register
    @mac_prefix = 'fdah7usad782345@'
    @db_name = "development"
    @db_config = YAML.load_file("/opt/rb/var/www/rb-rails/config/database.yml")
 
    @BKDF2_ITERATIONS = 10
    @PBKDF2_KEYSIZE = 6
    @HEX_CHARS = "0123456789abcdef".chars.to_a
    
    @ts_start = Time.now
    @scrambles = Hash.new
    
    update_salt
  end
  
  def filter(event)
    
    # Get data once by minute
    ts_end = Time.now - @ts_start
    if ts_end >= 60 then
      update_salt
      @ts_start = Time.now
      @logger.info("[Macscrambling] Loaded Scrambles")
    end
    
    if !@scrambles
      @logger.info("[Macscrambling] No scrambles in database")
    end

    mac = event.get("client_mac")
    spUUID = event.get("service_provider_uuid")
    begin
      if @scrambles.key?(spUUID.to_s)
        scramble = @scrambles[spUUID.to_s]
        salt = @scrambles[spUUID.to_s]["mac_hashing_salt"]
        prefix = @scrambles[spUUID.to_s]["mac_prefix"]
        if scramble and mac then
          # Decode Hexadecimal value, scramble it and write to the mac format
          decoded_mac_scramble = scramble_mac(mac, prefix, salt)
          decoded_mac_scramble_to_mac = to_mac(decoded_mac_scramble, ":")
          event.set("client_mac",decoded_mac_scramble_to_mac)
        end
      end
    rescue => e
      @scrambles = Hash.new
      @logger.error("[MacScrambling] General security exception:" + e.to_s)
    end
    filter_matched(event)
  end  # def filter
  
  def scramble_mac(_mac, _prefix, _salt)
    digest_key = nil
    begin
      array_a = _prefix.to_s.bytes.to_a
      array_b = [_mac.gsub(":","")].pack('H*').bytes.to_a
      key = (array_a << array_b).flatten
      salty = _salt.bytes.to_a
      digest_key = OpenSSL::PKCS5.pbkdf2_hmac(key.to_s, salty.to_s, @BKDF2_ITERATIONS, @PBKDF2_KEYSIZE, 'sha256')
    rescue => e
      digest_key = nil
      @logger.error("[MacScrambling] OpenSSL:" + e.to_s)
    end
    return digest_key
  end # def scramble_mac
  
  def to_mac(value, separator)
    String final_s = String.new
    i=0
    byte_array = value.bytes.to_a
    while i < byte_array.length
      if i>0
        final_s << separator
      end
      final_s << @HEX_CHARS[(byte_array[i] >> 4) & 15]
      final_s << @HEX_CHARS[byte_array[i] & 15]
      
      i+=1
    end
    
    return final_s
  end # def to_mac
  
  
  # Connect to Postgresql DB to get information from sensors
  def update_salt
    begin      
      # PG connection
      db =  PG.connect(dbname: @db_config[@db_name]["database"], user: @db_config[@db_name]["username"], password: @db_config[@db_name]["password"], port: @db_config[@db_name]["port"], host: @db_config[@db_name]["host"])
          
      @scrambles = Hash.new
      # Get sensor info from PG
      db.exec("SELECT uuid, property FROM sensors WHERE domain_type=6;") do |result|
        result.each do |row|
              
          #"Property" field has a json embessed
          json_content = JSON.parse(row["property"])
          
          # Decoding from Hexadecimal to string
          salt = [json_content["mac_hashing_salt"].to_s].pack('H*')
          
          @scrambles[row["uuid"].to_s] = Hash.new
          @scrambles[row["uuid"].to_s]["mac_hashing_salt"] = salt.to_s
          @scrambles[row["uuid"].to_s]["mac_prefix"] = @mac_prefix.to_s
        end
      end
    
    rescue  => e
      @scrambles = Hash.new
      @logger.error("[MacScrambling] Database:" + e.to_s)
    ensure
      db.close if db
    end
  end  # def update_salt
end    # class Logstash::Filter::MacScrambling

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
  #config :mac_prefix, :validate => :string, :default => "fdah7usad782345@", required => false  
  
  public
  def register
    @logger.info("[Macscrambling] testing: Register")
    @mac_prefix = 'fdah7usad782345@'
    @db_name = "development"
    @db_config = YAML.load_file("/opt/rb/var/www/rb-rails/config/database.yml")
 
    @BKDF2_ITERATIONS = 10
    @PBKDF2_KEYSIZE = 48
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
      @logger.info("[Macscrambling] No scrambles in DB")
    end

    mac = event.get("client_mac")
    spUUID = event.get("service_provider_uuid")
    begin
      if @scrambles.key?(spUUID.to_s)
        scramble = @scrambles[spUUID.to_s]
        salt = @scrambles[spUUID.to_s]["mac_hashing_salt"]
        prefix = @scrambles[spUUID.to_s]["mac_prefix"]
        @logger.info("[MacScrambling] testing: mac:" + mac.to_s + ", salt:" + salt.to_s + ", prefix:" + prefix.to_s)
        if scramble and mac then
          # Decode Hexadecimal value, scramble it and write to the mac format
          decoded_mac_scramble = scramble_mac(mac, prefix, salt)
          @logger.info("[Macscrambling] testing: scrambled mac: " + decoded_mac_scramble)
          @logger.info("[Macscrambling] testing: scrambled mac: " + decoded_mac_scramble.bytes.to_a.to_s)

          decoded_mac_scramble_to_mac = to_mac(decoded_mac_scramble, ":")
          @logger.info("[Macscrambling] testing: mac:" + decoded_mac_scramble_to_mac.to_s)
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
    # TODO: checkFinalValues In Java there are signed bytes
    digest_key = nil
    begin
      array_a = _prefix.to_s.bytes.to_a
      array_b = [_mac.gsub(":","")].pack('H*').bytes.to_a
      key = (array_a << array_b).flatten
      @logger.info("[Macscrambling] testing: key:" + key.to_s)
      #salty = [_salt].pack('H*').bytes.to_a
      salty = _salt.bytes.to_a
      @logger.info("[Macscrambling] testing: salt:" + salty.to_s)
      digest_key = OpenSSL::PKCS5.pbkdf2_hmac(key.to_s, salty.to_s, @BKDF2_ITERATIONS, @PBKDF2_KEYSIZE/8, 'sha256')
      #digest_key = OpenSSL::PKCS5.pbkdf2_hmac('fdah7usad782345@000000000000','pepe', @BKDF2_ITERATIONS, @PBKDF2_KEYSIZE/8, 'sha256') 
    rescue => e
      digest_key = nil
      @logger.error("[MacScrambling] OpenSSL:" + e.to_s)
    end
    return digest_key
  end # def scramble_mac
  
  def to_mac(value, separator)
    #TODO: recheck values
    String final_s = String.new
    i=0
    byte_array = value.bytes.to_a
    #emulation of replacing negative number what represents a byte in Java, x>=128
    #byte_array.map! { |v| v >= 128 ? 4 : v }
    @logger.info("[Macscrambling] byte_array: " + byte_array)
    while i < byte_array.length
      if i>0
        final_s << separator
      end
      #@logger.info("[Macscrambling] while: " + value[i].chr)
      #positive_number = if (!value[i].chr.is_a? Numeric || value[i].to_i < 0) then 4 else value[i] end
      #positive_number = if (!value[i].chr.is_a? Numeric || value[i].chr.to_i < 0) then 4 else value[i].to_i end
      #a.map! { |val| val >= 128 ? 4 : val }
      
      #index1 = byte_array[i].chr.to_i # & 0x0F
      #index2 = value[i].chr.to_i # & 0x0F
      #final_s << @HEX_CHARS[index1]
      #final_s << @HEX_CHARS[index2]
      #sb.append(HEX_CHARS[(val[a] >> 4) & 0x0F]);
      #      sb.append(HEX_CHARS[val[a] & 0x0F]);
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
          @scrambles[row["uuid"].to_s]["mac_prefix"] = @mac_prefix.to_s # .bytes.to_a   #to Byte array
        end
      end
      #@logger.info("[MacScrambling] testing: Database keys:" + @scrambles.keys.to_s) # For testing
    
    rescue  => e
      @scrambles = Hash.new
      @logger.error("[MacScrambling] Database:" + e.to_s)
    ensure
      db.close if db
    end
  end  # def update_salt
end    # class Logstash::Filter::MacScrambling

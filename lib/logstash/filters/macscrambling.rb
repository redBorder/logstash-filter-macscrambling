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
require 'openssl'


class LogStash::Filters::MacScrambling < LogStash::Filters::Base

  config_name "macscrambling"

  public
  def register
    @db_name = "development"
    @db_config = YAML.load_file("/opt/rb/var/www/rb-rails/config/database.yml")

    @BKDF2_ITERATIONS = 10
    @PBKDF2_KEYSIZE = 48
    @HEX_CHARS = "0123456789abcdef".chars.to_a

    @ts_start = Time.now
    @scrambles = Hash.new
    @mac_prefix_fromConfig = "123" #TODO ->config.get("redborder.macscramble.prefix");
    @mac_prefix_default = "fdah7usad782345@"

    update_salt
  end

  def filter(event)

    # Get data once by minute
    ts_end = Time.now - @ts_start
    if ts_end >= 60 then
      update_salt
      @ts_start = Time.now
    end
    
    mac = event.get("client_mac")
    spUUID = event.get("service_provider_uuid")

    begin
      scramble = @scrambles[spUUID.to_s]
      salt = @scrambles[spUUID.to_s]["mac_hashing_salt"]
      prefix = @scrambles[spUUID.to_s]["mac_prefix"]
      
      if scramble and mac then     
        # Decode Hexadecimal value, scramble it and write to the mac format
        decoded_mac = [mac.gsub(":","").to_s].pack('H*')
        decoded_mac_screamble = scramble_mac(decoded_mac, prefix, salt)
        decoded_mac_screamble_to_mac = to_mac(decoded_mac_screamble, ":")

        message.put("client_mac",decoded_mac_screamble_to_mac)
      end
    rescue
      @scrambles = Hash.new
      puts "GeneralSecurityException"
    end
  end  # def filter

  def scramble_mac(_mac, _prefix, _salt)
    # TODO: checkFinalValues In Java there are signed bytes
    digest_key = nil
    begin
      key = _prefix<<_mac
      digest_key = OpenSSL::PKCS5.pbkdf2_hmac(key, _salt, @BKDF2_ITERATIONS, @PBKDF2_KEYSIZE/8, 'sha256')
    rescue
      digest_key = nil
      puts "GeneralSecurityException, OpenSSL"
    end
    return digest_key
  end # def scramble_mac

  def to_mac(value, separator)
    #TODO: recheck values
    String final_s = String.new
    i=0
    while i < value.length
      if i>0
        final_s<<separator
      end
      positive_number = if (!value[i].chr.is_a? Numeric || value[i].chr.to_i < 0) then 4 else value[i] end
      final_s<<HEX_CHARS[positive_number & 0x0F]
      final_s<<HEX_CHARS[value[i] & 0x0F]
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
          @scrambles[row["uuid"].to_s]["mac_hashing_salt"] = salt  

          if mac_prefix_fromConfig and !mac_prefix_fromConfig.to_s.strip.empty?
            @scrambles[row["uuid"].to_s]["mac_prefix"] = @mac_prefix_fromConfig.bytes.to_a   #to Byte array
          else
            @scrambles[row["uuid"].to_s]["mac_prefix"] = @mac_prefix_default.bytes.to_a #to Byte array
          end
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

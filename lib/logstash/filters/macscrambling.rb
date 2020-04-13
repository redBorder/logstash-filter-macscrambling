# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"

require 'pg'
require 'json'
require 'yaml'
require 'fileutils'
require 'socket'
require 'openssl'
require 'time'
require 'dalli'


class LogStash::Filters::Macscrambling < LogStash::Filters::Base
  
  config_name "macscrambling"
  config :memcached_server,  :validate => :string, :default => "",  :required => false
  
  public
  def register
    # Constant
    @BKDF2_ITERATIONS = 10
    @PBKDF2_KEYSIZE = 6
    @HEX_CHARS = "0123456789abcdef".chars.to_a
    
    @memcached_server = MemcachedConfig::servers.first if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0, :value_max_bytes => 4000000}) 
    @scrambles = @memcached.get("scrambles") || {}
    @mac_prefix = @memcached.get("mac_prefix") || ''
    @last_refresh_stores = nil
    
  end #def register
  

  def refresh_stores
    return nil unless @last_refresh_stores.nil? || ((Time.now - @last_refresh_stores) > (60 * 5))
    @last_refresh_stores = Time.now
    e = LogStash::Event.new
    e.set("refresh_stores",true)
    return e
  end # def refresh_stores
  
  def filter(event)
    
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
    event_refresh = refresh_stores
    yield event_refresh if event_refresh

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
  
end # class Logstash::Filter::MacScrambling

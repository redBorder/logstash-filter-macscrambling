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

require_relative "util/memcached_config"

class LogStash::Filters::Macscrambling < LogStash::Filters::Base
  
  config_name "macscrambling"
  config :memcached_server,  :validate => :string, :default => nil,  :required => false
   
  public
  def register
    # Constant
    @mac_prefix = "fdah7usad782345@" 
    @memcached_server = MemcachedConfig::servers unless @memcached_server
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0, :value_max_bytes => 4000000}) 
    @scrambles = @memcached.get("scrambles") || {}
    
  end #def register
  
  def filter(event)
    unless @scrambles.empty?
      mac = event.get("client_mac")
      sp_uuid = event.get("service_provider_uuid")
      if mac && sp_uuid 
        begin
          scramble = @scrambles[sp_uuid] if @scrambles[sp_uuid]
          if scramble
            salt = scramble["mac_hashing_salt"] if scramble["mac_hashing_salt"]
            prefix = scramble["mac_prefix"] || @mac_prefix
            if salt
              key = "#{prefix}#{mac.gsub(':','')}"
              client_mac = OpenSSL::PKCS5.pbkdf2_hmac_sha1(key,salt,10,6) \
                                         .unpack('C*') \
                                         .map{ |b| "%02X" % b } \
                                         .join('') \
                                         .scan(/../) \
                                         .join(":").downcase 

              event.set("client_mac",client_mac)
              #event.set("original_client_mac",mac)
            end
          end
        rescue => e
          @logger.error("[MacScrambling] Exception:" + e.to_s)
        end
      end
    end
    
    filter_matched(event)
  end  # def filter
  
 
end # class Logstash::Filter::MacScrambling

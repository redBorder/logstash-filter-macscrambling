# encoding: utf-8
require 'spec_helper'
require "logstash/filters/macscrambling"

describe LogStash::Filters::MacScrambling do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        macscrambling {
          message => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject.get("message")).to eq('Hello World')
    end
  end
end

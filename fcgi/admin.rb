#!/usr/bin/env ruby
$LOAD_PATH << File.dirname(__FILE__)
require 'rubygems'
require 'syslog'
require 'digest/sha1'
require 'base64'
require 'securerandom'
require 'uri'
require 'timeout'
require 'ldap'
require 'fcgi'
require 'admin_control.rb'
include ERB::Util


Syslog.open("FastCGI.Admin",
  Syslog::LOG_PID|Syslog::LOG_CONS, Syslog::LOG_DAEMON)

#
# handle FastCGI request
#
def main()
  Syslog.info("Starting FastCGI server (ruby #{RUBY_VERSION})")
  load_path = File.dirname(__FILE__)
  control = AdminControl.new(load_path, false)

  FCGI.each_request do |request|
    begin
    timeout(10) do
      control.input(request)
    end
    rescue => e
      raise e
    ensure
      request.finish()
    end
  end
end

#
# auto-reload
#
begin
  main()
rescue => e
  Syslog.crit("Fatal Exception in FastCGI server: #{e.to_s}")
  trace = e.backtrace.join('\n')
  Syslog.crit("#{trace}")
  sleep(10)
  retry
end

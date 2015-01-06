#!/usr/bin/env ruby
$LOAD_PATH << File.dirname(__FILE__)
require 'admin_control.rb'
require 'dummy_stub.rb'
#require 'ldap'

class Request
  attr_accessor :env, :in, :out

  def initialize(env)
    @env = env
    @in = STDIN
    @out = STDOUT
  end
end

def main()
  print "Ruby #{RUBY_VERSION}\n"
  control = AdminControl.new(".", true)


  #
  # Main loop
  #
  env_list = [
    {
      'SCRIPT_NAME' => "/admin/login",
      'REQUEST_METHOD' => "GET",
      'QUERY_STRING' => nil,
      'HTTP_HOST' => "localhost",
    },
    {
      'SCRIPT_NAME' => "/admin/login",
      'REQUEST_METHOD' => "GET",
      'QUERY_STRING' => "submit=login&userid=testuser@floatlink.jp&password=hogehoge",
      'HTTP_HOST' => "localhost",
    },
    {
      'SCRIPT_NAME' => "/admin/passwd",
      'REQUEST_METHOD' => "GET",
      'QUERY_STRING' => "submit=modify&password=hogehoge&password_retype=hogehoge",
      'HTTP_HOST' => "localhost",
    }
  ]

  cookie = nil
  n = 0
  env_list.each do |env|
    n = n + 1
    puts("==== TEST CASE #{n} ====")
    env['HTTP_COOKIE'] = cookie
    request = Request.new(env)
    html = control.input(request)
    html.each_line do |line|
      case line
      when /^Set-Cookie:/
        token = line.split(" ")
        cookie = token[1]
        cookie.chop!()
        puts("====> New Cookie: #{cookie}")
      end
    end
  end
end
main()

#!/usr/bin/env ruby
require 'rubygems'
require 'syslog'
require 'fcgi'
require 'uri'
require 'timeout'
require '/home/www/fcgi/admin_session.rb'
require '/home/www/fcgi/admin_handler.rb'
require '/home/www/fcgi/admin_ldap.rb'
include ERB::Util

#
# Utilites
#
def debug_env(request)
  request.out.print("<div><pre>\n")
  request.env.each_pair do |key, value|
    request.out.print("#{key}: #{value}\n")
  end
  request.out.print("</pre></div>\n")
end

def getquery(request)
  limit = 1024

  case request.env['REQUEST_METHOD']
  when /(GET|PUT)/
    rawstring = request.env['QUERY_STRING']
  when 'POST'
    lenstr = request.env['CONTENT_LENGTH']
    return {} unless lenstr
    len = lenstr.to_i()
    reutrn {} if len > limit
    begin
      timeout(10) do
        rawstring = request.in.read(len)
      end
    rescue Timeout::Error
      rawstring = nil
    end
  else
    rawstring = nil
  end
  return {} unless rawstring
  return {} if rawstring.size == 0
  rawstring = URI.unescape(rawstring)

  query = {}
  query_pair = rawstring.split('&')
  query_pair.each do |pair|
    keyvalue = pair.split('=', 2)
    if keyvalue[1]
      query[keyvalue[0]] = keyvalue[1]
    else
      query[keyvalue[0]] = ""
    end
  end

  query
end

def check_access(request)
  referer = request.env['REFERER']
  return true if referer == nil || referer == ""

  referer_u = URI::parse(referer)
  case referer_u.host
  when "www.sakura-mochi.net"
    true
  when "sakura-mochi.net"
    true
  when "www.floatlink.jp"
    true
  when "floatlink.jp"
    true
  else
    Syslog.err("CSRF: #{referer}")
    false
  end
end

def main()
  #
  # LDAP Handler
  #
  ldap = LDAPHandler.new()

  #
  # Template Binding
  #
  login_template =
    ERB.new(File.open("/home/www/fcgi/login.erb").read())
  logout_template =
    ERB.new(File.open("/home/www/fcgi/logout.erb").read())
  update_password_template =
    ERB.new(File.open("/home/www/fcgi/update_password.erb").read())
  templates = {
    :init => login_template,
    :login => login_template,
    :authdone => update_password_template,
    :logout => logout_template
  }

  #
  # Session Management
  #
  session = AdminSessionDB.new()
  raise RuntimeError unless session
  action = AdminSessionActionID.new()
  raise RuntimeError unless action

  #
  # Handler
  #
  login = Login.new(ldap, session, action, templates)
  raise RuntimeError unless login

  update_password = UpdatePassword.new(ldap, session, action, templates)
  raise RuntimeError unless update_password

  #
  # Main loop
  #
  FCGI.each_request do |request|
    # read request params
    resource = request.env['SCRIPT_NAME']
    query = getquery(request)
    if check_access(request) == false
      request.finish()
      next
    end
    Syslog.info("Request Received: \"#{resource}\"")

    # parse request
    case resource
    when /^\/admin\/login$/
      handler = login
    when /^\/admin\/password$/
      handler = update_password
    else 
      handler = login
    end
    Syslog.info("Handler: #{resource} => #{handler.name()}")
    handler.handle(query)

    # generate response
    request.out.print(handler.http_header())
    request.out.print(handler.reply_html())
#   debug_env(request)
    handler.finish()
    request.finish()

    Syslog.info("Session done.")
  end
end

Syslog.open("update_password.rb",
  Syslog::LOG_PID|Syslog::LOG_CONS, Syslog::LOG_DAEMON)
begin
  Syslog.info("Starting FastCGI server")
  main()
rescue => e
  Syslog.crit("Fatal Exception in FastCGI server: #{e.to_s}")
  trace = e.backtrace.join('\n')
  Syslog.crit("#{trace}")
  sleep(10)
  retry
end
__END__

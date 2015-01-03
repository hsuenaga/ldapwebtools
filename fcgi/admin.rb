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
    begin
    timeout(10) do
      Syslog.info("Incoming Access")
      # read request params
      if check_access(request) == false
        request.finish()
        next
      end

      # parse request
      resource = request.env['SCRIPT_NAME']
      Syslog.info("Request Received: \"#{resource}\"")
      case resource
      when /^\/admin\/login$/
        handler = login
      when /^\/admin\/password$/
        handler = update_password
      else 
        handler = login
      end
      Syslog.info("Handler: #{resource} => #{handler.name()}")
      handler.handle(request)

      # generate response
      request.out.print(handler.reply_html())
#      debug_env(request)
      handler.finish()
      Syslog.info("Session done.")
    end
    rescue => e
      raise e
    ensure
      request.finish()
    end
  end
end

Syslog.open("FastCGI.Admin",
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

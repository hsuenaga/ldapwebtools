#!/usr/bin/env ruby
require 'rubygems'
require 'syslog'
require 'erb'
require 'cgi'
require 'uri'
require '/home/www/fcgi/admin_session.rb'
include ERB::Util

#
# Base Class
#
class AdminHandler
  attr_reader :name

  AUTH_WELCOME = "Welcome. Please input your User ID and Password"
  AUTH_TIMEOUT = "Session Timeout. Please login again."
  AUTH_ERROR_GENERIC = "NG.. Invalid User ID or Password"
  AUTH_SUCCESS_STRING = "OK!! User ID Confirmed"
  UPDATE_SUCCESS_STRING = "OK!! Password Updated"

  COOKIE_AUTH_TOKEN = "auth_token"

  def initialize(ldap, session, action, templates)
    @name = "Default Handler"
    @ldap = ldap
    @templates = templates
    @mydomain = ""
    @nextpage = :init
    @userid = ""
    @password = ""
    @password_new = ""
    @password_retype = ""
    @logout = ""
    @response = ""
    @cookie_issue = []
    @cookie_recv = {}

    #
    # external state presentation name mapping
    #
    @nextpage_map = action.action_map
    @nextpage_map_inv = action.action_map_inv

    #
    # session control
    #
    @sessiondb = session
    @session = nil 
  end

  def log(message, *args)
    Syslog.info(message, *args)
  end

  def log_err(message,*args)
    Syslog.err(message, *args)
  end

  def clear_new_password()
    @password_new = ""
    @password_retype = ""
  end

  def clear_form()
    @userid = ""
    @password = ""
    @session = ""
    clear_new_password()
  end

  def finish()
    clear_form()
    @nextpage = :init
  end

  def set_cookie(cookie)
    @cookie_issue << cookie
  end

  def check_userid()
    if @userid == ""
      @response = "NG.. Please input userid"
      return false
    end
    true
  end

  def check_password()
    if @password == ""
      @response = "NG.. Please input old password"
      return false
    end
    true
  end

  def check_new_password()
    if @password_new == ""
      @response = "NG.. Please input new password"
      clear_new_password()
      return false
    end

    if @password_retype == ""
      @response = "NG.. Please retype new password"
      clear_new_password()
      return false
    end

    if @password_new != @password_retype
      @response = "NG.. New password mismatch"
      clear_new_password()
      return false
    end

    if @password_new.size() < 8
      @response = "NG.. Too short password (8-32 chars)"
      clear_new_password()
      return false
    elsif @password_retype.size() > 32
      @response = "NG.. Too long password (8-32 chars)"
      clear_new_password()
      return false
    end
    true
  end

  def parse_pageid(pageid)
    return @nextpage_map_inv.default unless pageid
    @nextpage_map_inv[pageid]
  end

  def pageid(nextpage)
    return @nextpage_map.default unless nextpage
    @nextpage_map[nextpage]
  end

  def parse_subst(string, delim = ' ')
    return {} if string == nil || string == ""

    args = {}
    args_pair = string.split(delim)
    args_pair.each do |pair|
      keyvalue = pair.split('=', 2)
      if keyvalue[1]
        args[keyvalue[0]] = keyvalue[1]
      else
        args[keyvalue[0]] = ""
      end
    end

    args
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
      rawstring = request.in.read(len)
    else
      rawstring = nil
    end
    return {} unless rawstring
    return {} if rawstring.size == 0
    rawstring = URI.unescape(rawstring)

    parse_subst(rawstring, '&')
  end

  def auth_token_issue()
    @session = @sessiondb.new_session(@userid, @password)
    log("New Session: %s", "#{@session}")
    timeout = Time.new() + @session.timeout()
    cookie = CGI::Cookie.new({'name' => COOKIE_AUTH_TOKEN,
                              'value' => "#{@session}",
                              'expires' => timeout,
                              'domain' => "#{@myname}",
                              'path' => "/admin/",
                              'secure' => true})
    set_cookie(cookie) if cookie
  end

  def auth_token_inval()
    if @userid
      @sessiondb.del_userid(@userid)
    end
  end

  def auth_token_parse(request)
    @cookie_recv = {}
    source = request.env['HTTP_COOKIE']
    return false if source == nil || source == "" 

    @cookie_recv = parse_subst(request.env['HTTP_COOKIE'])
    auth_token_raw = @cookie_recv[COOKIE_AUTH_TOKEN]
    if auth_token_raw
      auth_token = CGI::unescape(auth_token_raw)
      log("Session ID: %s => %s", auth_token_raw, auth_token)
      @session = @sessiondb.resume_session(auth_token)
      if @session
        @userid = @session.userid
        @password = @session.password
        log("Session Resumed")
      else
        @userid = ""
        @password = ""
        log("No Session Available")
      end

      return true
    end
    false
  end

  def handle(request)
    # requested domain
    @myname = request.env['HTTP_HOST']

    # resume auth
    if auth_token_parse(request) == false
      @userid = ""
      @password = ""
    end

    query = getquery(request)
    if query.has_key?('nextpage')
      @nextpage = parse_pageid(query['nextpage'])
    else
      @nextpage = :init
    end
#    sessionid = query['sessionid'] if query.has_key?('sessionid')
#    if sessionid && sessionid != ""
#      log("Session ID: %s", sessionid)
#      @session = @sessiondb.resume_session(sessionid)
#      if @session
#        @userid = @session.userid
#        @password = @session.password
#      else
#        log("Session Available")
#        @session = nil
#      end
#    end
    @userid = query['userid'] if query.has_key?('userid')
    @password = query['password'] if query.has_key?('password')
    @password_new = query['password_new'] if query.has_key?('password_new')
    @password_retype = query['password_retype'] if query.has_key?('password_retype')
    @logout = query['logout'] if query.has_key?('logout')
  end

  def http_header()
    header = ""
    header += "Content-Type: text/html\r\n"
    @cookie_issue.each do |cookie|
      header += "Set-Cookie: #{cookie}\r\n"
      log("Cookie-Issue: %s", cookie)
    end
    header += "\r\n"
    @cookie_issue = []

    header
  end

  def reply_html()
    contents = ""
    if !@templates[@nextpage]
      return "ERROR: No Template(state: #{@nextpage}"
    end
    log("NextPage => #{@nextpage}")
    contents += http_header()
    contents += @templates[@nextpage].result(binding)

    File.open("/tmp/contents.tmp", "w") do |f|
       f.puts contents
    end

    contents
  end
end # class AdminHandler

#
# Login Screen
#
class Login < AdminHandler

  def initialize(ldap, session, action, template)
    super(ldap, session, action, template)
    @name = "Login"
  end

  def try_login()
      @response = AUTH_ERROR_GENERIC

      log("Checking Form(#{@nextpage})")
      return false unless check_userid()
      return false unless check_password()

      log("Checking LDAP(#{@nextpage})")
      if !@ldap.anon_bind()
        log("LDAP: #{@ldap.error}")
        return false
      end

      if !@ldap.is_user_exist?()
        log("LDAP: #{@ldap.error}")
        return false
      end

      if !@ldap.userid_bind()
        log("LDAP: #{@ldap.error}")
        return false
      end

      if !@ldap.unbind()
        log("LDAP: #{@ldap.error}")
        return false
      end

      @response = AUTH_SUCCESS_STRING
      true
  end

  def handle(request)
    super(request)

    case @nextpage
    when :init
      log("Create New FORM(#{@nextpage})")
      clear_form()
      @response = AUTH_WELCOME
      @nextpage = :login
    when :login
      @ldap.userid = @userid
      @ldap.password = @password
      if try_login()
        auth_token_issue()
        @nextpage = :authdone
      end
    else
      log_err("Invalid State(#{@nextpage})")
      clear_form()
      @response = AUTH_TIMEOUT
      @nextpage = :login
    end

    log("Response: #{@response}")
  end
end # Class Login < AdminHandler

#
# Password Screen
#
class UpdatePassword < AdminHandler
  def initialize(ldap, session, action, template)
    super(ldap, session, action, template)
    @name = "UpdatePassword"
  end

  def try_update()
    @response = AUTH_ERROR_GENERIC

    log("Checking Form(#{@nextpage})")
    return false unless check_userid()
    return false unless check_password()
    return false unless check_new_password()

    log("Update LDAP(#{@nextpage})")
    if !@ldap.userid_bind()
      log("LDAP: #{@ldap.error}")
      return false
    end

    if !@ldap.mod_userPassword(@password_new)
      log("LDAP: #{@ldap.error}")
      return false
    end

    if !@ldap.unbind()
      log("LDAP: #{@ldap.error}")
      return false
    end

    @response = UPDATE_SUCCESS_STRING
    true
  end

  def handle(request)
    super(request)

    case @nextpage
    when :authdone
      log("Checking Form(#{@nextpage})")
      @ldap.userid = @userid
      @ldap.password = @password
      if try_update()
        clear_form()
        @nextpage = :logout
      end
    when :logout
      if @logout == "yes"
        log("User Logout(#{@nextpage})")
        auth_token_inval()
        log("Refresh FORM(#{@nextpage})")
        clear_form()
        @response = AUTH_WELCOME
        @nextpage = :login
      end
    else
      log_err("Invalid State(#{@nextpage})")
      clear_form()
      @response = AUTH_TIMEOUT
      @nextpage = :login
    end
    log("Response: #{@response}")
  end
end # Class UpdatePassword < AdminHandler

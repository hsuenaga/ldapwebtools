#!/usr/bin/env ruby
require 'rubygems'
require 'syslog'
require 'erb'
require 'uri'
require '/home/www/fcgi/admin_session.rb'
include ERB::Util

#
# Base Class
#
class AdminHandler
  attr_reader :name

  AUTH_WELCOME = "Welcome. Please input your User ID and Password"
  AUTH_ERROR_GENERIC = "NG.. Invalid User ID or Password"
  AUTH_SUCCESS_STRING = "OK!! User ID Confirmed"
  UPDATE_SUCCESS_STRING = "OK!! Password Updated"

  def initialize(ldap, session, action, templates)
    @name = "Default Handler"
    @ldap = ldap
    @templates = templates
    @nextpage = :init
    @userid = ""
    @password = ""
    @password_new = ""
    @password_retype = ""
    @logout = ""
    @response = ""

    #
    # external state presentation name mapping
    #
    @nextpage_map = action.action_map
    @nextpage_map_inv = action.action_map_inv

    #
    # session control
    #
    @sessiondb = session
    @sessionid = ""
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
    @sessionid = ""
    clear_new_password()
  end

  def finish()
    clear_form()
    @nextpage = :init
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

  def handle(query)
    if query.has_key?('nextpage')
      @nextpage = parse_pageid(query['nextpage'])
    else
      @nextpage = :init
    end
    @sessionid = query['sessionid'] if query.has_key?('sessionid')
    if @sessionid && @sessionid != ""
      session = @sessiondb.resume_session(@sessionid)
      if session
        @userid = session.userid
        @password = session.password
      else
        @sessionid = nil
      end
    end
    @userid = query['userid'] if query.has_key?('userid')
    @password = query['password'] if query.has_key?('password')
    @password_new = query['password_new'] if query.has_key?('password_new')
    @password_retype = query['password_retype'] if query.has_key?('password_retype')
    @logout = query['logout'] if query.has_key?('logout')
  end

  def http_header()
    header = ""
    header += "Content-Type: text/html\r\n"
    header += "\r\n"
  end

  def reply_html()
    if !@templates[@nextpage]
      return "ERROR: No Template(state: #{@nextpage}"
    end
    log("NextPage => #{@nextpage}")
    @templates[@nextpage].result(binding)
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

  def handle(query)
    super(query)

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
        @nextpage = :authdone
        @sessionid = @sessiondb.new_session(@userid, @password)
      end
    else
      log_err("Invalid State(#{@nextpage})")
      @response = AUTH_ERROR_GENERIC
      clear_form()
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

  def handle(query)
    super(query)

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
        log("Refresh FORM(#{@nextpage})")
        clear_form()
        @response = AUTH_WELCOME
        @nextpage = :login
      end
    else
      clear_form()
      @response = "NG.. Invalid State(#{@nextpage})"
      @nextpage = :login
    end
    log("Response: #{@response}")
  end
end # Class UpdatePassword < AdminHandler

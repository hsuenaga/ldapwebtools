#!/usr/bin/env ruby
require 'rubygems'
require 'syslog'
require 'digest/sha1'
require 'base64'
require 'securerandom'
require 'uri'
require 'timeout'
require 'ldap'
require 'admin_session.rb'
require 'admin_handler.rb'
require 'admin_handler_login.rb'
require 'admin_handler_password.rb'
require 'admin_handler_menu.rb'
require 'admin_ldap.rb'
include ERB::Util

class AdminControl
  def initialize(load_path, debug = false)
    #
    # LDAP Handler
    #
    @ldap = LDAPHandler.new()

    #
    # Actions
    #
    actions = []
    actions << :init
    actions << :login
    actions << :modify
    actions << :logout
    actions << :error
    @action = AdminSessionActionID.new(actions, true)
    raise RuntimeError unless @action

    #
    # Session Management
    #
    @session = AdminSessionDB.new()
    raise RuntimeError unless @session

    #
    # Handler
    #
    template = File.join(load_path, "login.erb")
    @login = Login.new(@ldap, @session, @action, template)
    raise RuntimeError unless @login

    template = File.join(load_path, "passwd.erb")
    @passwd = Passwd.new(@ldap, @session, @action, template)
    raise RuntimeError unless @passwd

    template = File.join(load_path, "menu.erb")
    @menu = Menu.new(@ldap, @session, @action, template)
    raise RuntimeError unless @menu

    @debug = debug
    @login.debug = @debug
    @passwd.debug = @debug
  end

  def log(message, *args)
    if @debug
      printf(message, *args)
      printf("\n")
    else
      Syslog.info(message, *args)
    end
  end

  def log_err(message,*args)
    if @debug
      printf(message, *args)
      printf("\n")
    else
      Syslog.err(message, *args)
    end
  end

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

  def input(request)
    # Access control
    return false unless  check_access(request)

    # parse request
    error = false
    resource = request.env['SCRIPT_NAME']
    log("Request Received: \"#{resource}\"")
    case resource
    when /^\/admin\/login$/
      handler = @login
    when /^\/admin\/passwd$/
      handler = @passwd
    when /^\/admin\/menu$/
      handler = @menu
    else 
      handler = @login
      error = true
    end

    log("Handler: #{resource} => #{handler.name()}")
    context = handler.handle_request(request)
    if context == nil
      log_err("No Context Received")
      error = true
    end
    handler.finish()
    if error
      context.close_session(@session)
      context.destination = :login
      context.action = :init
    end
    reflect(request, context)
  end

  def reflect(request, context)
    # generate response
    case context.destination
    when :login
      responder = @login
    when :passwd
      responder = @passwd
    when :menu
      responder = @menu
    else
      log_err("No Destination \"%s\" found. defaulting to login",
        context.destination)
      responder = @login
      context.action = :init
    end

    html = responder.reply_response(context)
    request.out.print(html) unless @debug
    debug_env(request) if @debug
    responder.finish()
    log("Session done.")
    if @debug
      return html
    end
    true
  end
end

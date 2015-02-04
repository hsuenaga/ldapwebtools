#!/usr/bin/env ruby
#
# Login Screen
#
class Login < AdminHandler
  FORM_ERROR_USERID = "Missing User ID."
  FORM_ERROR_PASSWD = "Missing Password."
  AUTH_WELCOME = "Welcome. Please input your User ID and Password"
  AUTH_TIMEOUT = "Session Timeout. Please login again."
  AUTH_ERROR_GENERIC = "NG.. Invalid User ID or Password"
  AUTH_SUCCESS_STRING = "OK!! User ID Confirmed"

  def initialize(ldap, session, action, template)
    super(ldap, session, action, template)
    @name = "login"
    @userid = ""
    @password = ""
    @user_info = nil
  end

  def clear_form()
    @userid = ""
    @password = ""
    @user_info = nil
  end

  def check_form()
    if @userid == nil || @userid == ""
      @session.guide = FORM_ERROR_USERID
      return false
    end
    if @password == nil || @password == ""
      @session.guide = FORM_ERROR_PASSWD
      return false
    end
    true 
  end

  def try_login()
      @guide = AUTH_ERROR_GENERIC

      log("Checking Form(#{@name})")
      return false unless check_form()

      log("Checking LDAP(#{@name})")
      if !@ldap.anon_bind()
        log("LDAP: #{@ldap.error}")
        return false
      end

      entry = @ldap.search_user()
      if !entry
        log("LDAP: #{@ldap.error}")
        return false
      end
      log("ldap entry: %s", entry)
      @user_info = entry

      if !@ldap.userid_bind()
        log("LDAP: #{@ldap.error}")
        return false
      end

      if !@ldap.unbind()
        log("LDAP: #{@ldap.error}")
        return false
      end

      @guide = AUTH_SUCCESS_STRING
      true
  end

  def handle_request(request)
    super(request)

    @context.close_session(@sessiondb)

    @userid = @context.query['userid']
    @password = @context.query['password']
    if @userid == "" && @password == ""
      @context.destination = :login
      @context.action = :init
      return @context
    end

    @ldap.userid = @userid
    @ldap.password = @password
    if try_login()
      @context.new_session(@sessiondb, @userid, @password)
      @session = @context.session
      if @session
        @session.guide = @guide
        @session.user_info = @user_info
        log("GUIDE: %s", @session.guide)
        log("USER INFO: %s", @session.user_info)
      end
      @context.destination = :menu
      @context.action = :init
    else
      @context.destination = :login
      @context.action = :login
    end

    @context
  end

  def reply_response(context)
    @context = context
    log("Reply: #{@name}.#{@context.action}")
    case @context.action
    when :init
      log("Create New FORM(#{@name}.#{@context.action})")
      clear_form()
      @guide = AUTH_WELCOME
    when :login
      log("Retry FORM(#{@name}.#{@context.action})")
    when :error
      log("Create Error FORM(#{@name}.#{@context.action})")
      clear_form()
    end

    super(context)
  end
end # Class Login < AdminHandler

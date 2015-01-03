#!/usr/bin/env ruby
#
# Password Screen
#
class UpdatePassword < AdminHandler
  PASSWD_WELCOME = "Please input new password"
  AUTH_ERROR_SESSION = "NG.. Session Expired"
  FORM_ERROR_PASSWD = "NG.. Missing Password"
  FORM_ERROR_RETYPE = "NG.. Retype Password"
  FORM_ERROR_MISMATCH = "NG.. Password mismatch"
  UPDATE_SUCCESS_STRING = "OK!! Password Updated"

  def initialize(ldap, session, action, template)
    super(ldap, session, action, template)
    @name = "passwd"
    @password = ""
    @password_retype = ""
  end

  def clear_form()
    @password = ""
    @password_retype = ""
  end

  def check_form()
    @password = @context.query['password']
    @password_retype = @context.query['password_retype']

    if @password == nil || @password == ""
      @context.guide = FORM_ERROR_PASSWD
      return false
    end
    if @password_retype == nil || @password_retype == ""
      @context.guide = FORM_ERROR_RETYPE
      return false
    end
    if @password != @password_retype
      @context.guide = FORM_ERROR_MISMATCH
      return false
    end

    true
  end

  def try_update()
    @context.guide = AUTH_ERROR_SESSION

    log("Checking Form(#{@name})")
    return false unless check_form()

    log("Update LDAP(#{@name})")
    if !@ldap.userid_bind()
      log("LDAP: #{@ldap.error}")
      return false
    end

    if !@ldap.mod_userPassword(@password)
      log("LDAP: #{@ldap.error}")
      return false
    end

    if !@ldap.unbind()
      log("LDAP: #{@ldap.error}")
      return false
    end

    @context.guide = UPDATE_SUCCESS_STRING
    true
  end

  def handle_request(request)
    super(request)

    userid = @context.userid()
    password = @context.password()
    if !userid || !password || userid == "" || password == ""
      log("Broken Session")
      @context.guide = AUTH_ERROR_SESSION
      @context.destination = :login
      @context.action = :error
      return @context
    end

    @ldap.userid = userid
    @ldap.password = password
    if try_update()
      clear_form()
      @context.destination = :login
      @context.action = :init
    else
      clear_form()
      @context.destination = :passwd
      @context.action = :modify
    end

    @context
  end

  def reply_response(context)
    @context = context
    log("Reply: #{@name}.#{@context.action}")

    case @context.action
    when :init
      clear_form()
      @context.guide = PASSWD_WELCOME
      @context.action = :modify
    end

    super(context)
  end
end # Class UpdatePassword < AdminHandler

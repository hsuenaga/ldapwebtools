#!/usr/bin/env ruby
#
# Login Screen
#
class Menu < AdminHandler

  def initialize(ldap, session, action, template)
    super(ldap, session, action, template)
    @name = "menu"
    @userid = ""
    @passwd = ""
  end

  def handle_request(request)
    super(request)

    @context.action = :init
    @context
  end

  def reply_response(context)
    @context = context
    log("Reply: #{@name}.#{@context.action}")
    case @context.action
    when :init
      log("Create New FORM(#{@name}.#{@context.action})")
    when :error
      log("Create Error FORM(#{@name}.#{@context.action})")
    end

    super(context)
  end
end # Class Login < AdminHandler

#!/usr/bin/env ruby
#
# Login Screen
#
class Logout < AdminHandler
  def initialize(ldap, session, action, template)
    super(ldap, session, action, template)
    @name = "logout"
  end

  def handle_request(request)
    super(request)

    @context.close_session(@sessiondb)
    @context.destination = :login
    @context.action = :init
    @context
  end

  def reply_response(context)
    # no logout screen defined.
  end
end # Class Logout < AdminHandler

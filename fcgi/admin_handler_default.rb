#!/usr/bin/env ruby
#
# Login Screen
#
class Default < AdminHandler
  def initialize(ldap, session, action, template)
    super(ldap, session, action, template)
    @name = "default"
  end

  def handle_request(request)
    super(request)

    @context.destination = :login
    @context.action = :init
    @context
  end

  def reply_response(context)
    # no default screen defined.
  end
end # Class Default < AdminHandler

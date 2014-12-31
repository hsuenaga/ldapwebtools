#!/usr/bin/env ruby
require 'digest/sha1'
require 'base64'
require 'securerandom'
require 'rubygems'
require 'erb'
require 'fcgi'
require 'ldap'

class LDAPUpdate
  attr_reader :error

  def ssha(string)
    tag = '{SSHA}'
    salt = SecureRandom.random_bytes(16)
    hash = Digest::SHA1.digest(string + salt)
    result = Base64.encode64(hash + salt).chomp!
    "#{tag}#{result}"
  end

  def userid2dn(mail)
    addrs = mail.split("@", 2)
    if addrs.count != 2
      return nil
    end
    domains = addrs[1].split('.')
    if domains.count != 2
      return nil
    end
    "uid=#{addrs[0]},ou=Users,ou=vMailbox,dc=#{domains[0]},dc=#{domains[1]}"
  end

  def initialize(ldap, userid, password_old, password_new)
    @ldap = ldap
    @userid = userid
    @password_old = password_old
    @password_new = password_new
    @error = ""
  end

  def do
    changepw = [
      LDAP::Mod.new(LDAP::LDAP_MOD_REPLACE,
         'userPassword', ["#{ssha(@password_new)}"])
    ]
    base = userid2dn(@userid)
    scope = LDAP::LDAP_SCOPE_SUBTREE
    filter = "(mailacceptinggeneralid=#{@userid})"
    attrs = ['dn']
    e = nil
    dn = nil
    begin
      @ldap.bind('', '', LDAP::LDAP_AUTH_SIMPLE) {
        @ldap.search(base, scope, filter, attrs) { |entry|
          dn = entry.dn
        }
      }
      if dn && dn == base
        @ldap.bind(dn, @password_old, LDAP::LDAP_AUTH_SIMPLE) {
          @ldap.modify(dn, changepw)
        }
      else
        @error = @error + "NG.. Invalid User ID or Password"
      end
    rescue LDAP::ResultError => e
      dn = nil
      @error = @error + "NG.. Invalid User ID or Password"
    end

    if !dn
      return false
    end

    @error = @error + "OK! userdn=#{dn}"
    return true
  end
end

class Authenticator
  def initialize(ldap = nil)
    @ldap = ldap
    @state = "initial"
    @userid = ""
    @password_old = ""
    @password_new1 = ""
    @password_new2 = ""
    @response = ""
  end

  def clear_form()
    @userid = ""
    @password_old = ""
    @password_new1 = ""
    @password_new2 = ""
  end

  def clear_password()
    @password_new1 = ""
    @password_new2 = ""
  end

  def check_form()
    if @userid == ""
      @response = "NG.. Please input userid"
      return false
    end
    if @password_old == ""
      @response = "NG.. Please input old password"
      return false
    end
    if @password_new1 == ""
      @response = "NG.. Please input new password"
      clear_password()
      return false
    end
    if @password_new2 == ""
      @response = "NG.. Please retype new password"
      clear_password()
      return false
    end
    if @password_new1 != @password_new2
      @response = "NG.. New password mismatch"
      clear_password()
      return false
    end
    if @password_new1.size() < 8
      @response = "NG.. Too short password (8-32 chars)"
      clear_password()
      return false
    else if @password_new2.size() > 32
      @response = "NG.. Too long password (8-32 chars)"
      clear_password()
      return false
    end
    end

    @response = "Form check OK." 
    true
  end

  def exec_ldap()
    handle = LDAPUpdate.new(@ldap, @userid, @password_old, @password_new1)
    if !@ldap 
      return "Sorry.. Our Service is Down."
    end
    return nil if handle.do()
    return handle.error()
  end

  def handle(cgi)
    @state = cgi['state'] if cgi.has_key?('state')
    @userid = cgi['userid']
    @password_old = cgi['password_old']
    @password_new1 = cgi['password_new1']
    @password_new2 = cgi['password_new2']

    case @state
    when "initial"
      clear_form()
      @response = "Welcome. Please fill above."
      @state = "check"
    when "check"
      if check_form()
        @response = exec_ldap()
        if @response == nil
          clear_form()
          @state = "check"
          @response = "OK!! Password updated successfully!"
        end
      end
    else
    end
  end

  def html()
    erb = ERB.new(DATA.read)
    erb.result(binding)
  end
end

def main()
  ldap = LDAP::Conn.new('localhost', LDAP::LDAP_PORT)
  exit unless ldap
  ldap.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)

  FCGI.each_cgi {|cgi|
    # parse request
    session = Authenticator.new(ldap)
    session.handle(cgi)

    # generate response
    puts cgi.header
    print session.html()
  }
end
main()
__END__
<html>
 <head>
   <title>Mail Password Update</title>
 </head>

 <body>
   <H1>Update Mail Password</H1>
   <form action="auth.rb" method="get">
     <div>
       <span>User ID</span>
       <input type="text" name="userid" value="<%="#{@userid}"%>">
     </div>
     
     <div>
       <span>Old Password</span>
       <input type="password" name="password_old" value="<%="#{@password_old}"%>">
     </div>
     <div>
       <span>New Password</span>
       <input type="password" name="password_new1" value="<%="#{@password_new1}"%>">
       <span>(8-32 chars)</span>
     </div>
     <div>
       <span>New Password(Retype)</span>
       <input type="password" name="password_new2" value="<%="#{@password_new2}"%>">
       <span>(8-32 chars)</span>
     </div>
     <div>
       <input type="submit" value="OK">
     </div>
     <input type="hidden" name="state" value="<%="#{@state}"%>">
   </form>
   <p>
     <div>
      <span><%="#{@response}"%></span>
     </div>
   </p>
 </body>
</html>

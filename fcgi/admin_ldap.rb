#!/usr/bin/env ruby

#
# LDAP Handling
#
class LDAPHandler
  attr_reader :error
  attr_writer :userid, :password

  INVALID_ID_FORMAT_STRING = "Invalid User ID Foramt"
  NO_ENTRY_STRING = "No Entry Found"
  DUPLICATED_ENTRY_STRING = "Duplicated User ID Found"
  BROKEN_RESPONSE_STRING = "Broken Server Response"

  class LDAPUser
    attr_reader :dn, :maildrop, :mailaddr
    def initialize(entry)
      @dn = entry.dn
      @maildrop = entry.vals('maildrop')
      @mailaddr = entry.vals('mailacceptinggeneralid')
    end
  end

  def initialize()
    @connection = LDAP::Conn.new('localhost', LDAP::LDAP_PORT)
    if !@connection
      Syslog.err("Cannot connect to LDAP")
      raise RuntimeError
    end
    @connection.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
    @userid = ""
    @password = ""
    @error = ""
  end

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
      @error = INVALID_ID_FORMAT_STRING
      return nil
    end
    domains = addrs[1].split('.')
    if domains.count != 2
      @error = INVALID_ID_FORMAT_STRING
      return nil
    end
    "uid=#{addrs[0]},ou=Users,ou=vMailbox,dc=#{domains[0]},dc=#{domains[1]}"
  end

  def default_bind()
    begin
      if !@connection.bound?
        @connection.bind('', '', LDAP::LDAP_AUTH_SIMPLE)
      end
    rescue LDAP::ResultError => e
      @error = e.to_s()
      return false
    end
    true
  end

  def anon_bind()
    begin
      if @connection.bound?
        @connection.unbind()
      end
      @connection.bind('', '', LDAP::LDAP_AUTH_SIMPLE)
    rescue LDAP::ResultError => e
      @error = e.to_s()
      return false
    end
    true
  end

  def userid_bind()
    dn = userid2dn(@userid)
    return false unless dn

    begin
      if @connection.bound?
        @connection.unbind()
      end
      @connection.bind(dn, @password, LDAP::LDAP_AUTH_SIMPLE)
    rescue LDAP::ResultError => e
      @error = e.to_s()
      return false
    end
    true
  end

  def unbind()
    return true unless @connection.bound?
    begin
      @connection.unbind()
    rescue LDAP::ResultError => e
      @error = e.to_s()
      return false
    end
    true
  end

  def search_user()
    dn = userid2dn(@userid)
    dn_found = nil
    scope = LDAP::LDAP_SCOPE_BASE
    filter = "(objectClass=mailAccount)"
    attrs = ['dn', 'maildrop', 'mailacceptinggeneralid']

    return false unless dn 
    return false unless default_bind()

    count = 0
    begin
      @connection.search(dn, scope, filter, attrs) do |entry|
        count += 1
        dn_found = LDAPUser.new(entry)
      end
    rescue LDAP::ResultError => e
      @error = e.to_s()
      return false
    end

    if count < 1
      @error = NO_ENTRY_STRING
      return false
    end

    if count > 1
      @error = DUPLICATED_ENTRY_STRING
      return false
    end

    if !dn_found || dn_found.dn != dn
      @error = BROKEN_RESPONSE_STRING
      return false
    end

    return dn_found
  end
  
  def serialize(userinfo)
    string = ""
    string += "DN: #{userinfo.dn}\n"
    string += "MAIL ADDRESS: #{userinfo.mailaddr}\n"
    string += "FORWARD:#{userinfo.maildrop}\n"
    string
  end

  def mod_userPassword(password_new)
    changepw = [
      LDAP::Mod.new(LDAP::LDAP_MOD_REPLACE,
         'userPassword', ["#{ssha(password_new)}"])
    ]
    dn = userid2dn(@userid)
    if dn == nil
      @error = INVALID_ID_FORMAT_STRING
      return false
    end

    begin
      @connection.modify(dn, changepw)
    rescue LDAP::ResultError => e
      @error = e.to_s()
      return false
    end
    true
  end
end

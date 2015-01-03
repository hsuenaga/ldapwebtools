#!/usr/bin/env ruby

class LDAP_Entry
  attr_reader :dn

  def initialize(dn)
    @dn = dn
  end
end

class LDAP
  LDAP_PORT = 0
  LDAP_OPT_PROTOCOL_VERSION = "LDAP_Version"
  LDAP_AUTH_SIMPLE = 0
  LDAP_SCOPE_BASE = 0
  LDAP_MOD_REPLACE = 0

  class ResultError < Exception
  end

  class Mod
    def initialize(opcode, attr, arg)
    end
  end

  class Conn
    def initialize(host, port)
      puts("LDAP::Conn.new(#{host}, #{port})")
    end

    def set_option(opt, value)
      puts("LDAP::Conn.set_option(#{opt} => #{value})")
    end

    def bound?()
      true
    end

    def unbind()
      true
    end

    def bind(dn, password, method)
      true
    end

    def search(dn, scope, filter, attr, &block)
      entry = LDAP_Entry.new(dn)
      block.call(entry)
    end

    def modify(dn, cmd)
      true
    end
  end

  def initialize
  end
end

class Request
  attr_accessor :env, :in, :out

  def initialize(env)
    @env = env
    @in = STDIN
    @out = STDOUT
  end
end

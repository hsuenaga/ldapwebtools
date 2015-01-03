#!/usr/bin/env ruby
require 'rubygems'
require 'securerandom'
require 'base64'

class AdminSession
  attr_reader :userid, :password, :sessionid, :timestamp, :timeout

  def initialize(userid, password, timeout)
    @userid = userid
    @password = password
    @sessionid = _new_sessionid()
    @timestamp = Time.now()
    @timeout = timeout
  end

  def _new_sessionid()
    return false if !@userid || @userid == ""
    return false if !@password || @password == ""
    AdminSession::cookie()
  end

  def self.cookie()
    "#{Base64.encode64(SecureRandom.random_bytes(16)).chomp!}"
  end

  def self.simple_cookie()
    "#{SecureRandom.hex(16)}"
  end

  def to_s()
    "#{@sessionid}"
  end
end

class AdminSessionDB
  attr_reader :timeout

  DEFAULT_TIMEOUT = (10 * 60)

  def initialize(timeout = DEFAULT_TIMEOUT)
    @db = []
    @timeout = DEFAULT_TIMEOUT
  end

  def new_session(userid, password, timeout = @timeout)
    del_userid(userid)

    session = AdminSession.new(userid, password, timeout)
    return false unless session
    @db << session
    session
  end

  def timeout_session()
    @db.delete_if do |session|
      (Time.now() - session.timestamp()).to_i() > session.timeout()
    end
    true
  end

  def resume_session(sessionid)
    timeout_session()
    @db.find do |session|
      session.sessionid == sessionid
    end
  end

  def del_userid(userid)
    timeout_session()
    @db.delete_if do |session|
      session.userid == userid
    end
  end

  def del_session(sessionid)
    timeout_session()
    @db.delete_if do |session|
      session.sessionid == sessionid
    end
  end
end

class AdminSessionActionID
  attr_reader :action_map, :action_map_inv

  def initialize()
    @action_map = {
      :init => AdminSession::simple_cookie(),
      :login => AdminSession::simple_cookie(),
      :authdone => AdminSession::simple_cookie(),
      :logout => AdminSession::simple_cookie(),
      :nomatch => AdminSession::simple_cookie()
    }
    @action_map.default = @action_map[:nomatch]
    @action_map_inv = @action_map.invert()
    @action_map_inv.default = :nomatch
  end
end

#!/usr/bin/env ruby
require 'rubygems'
require 'securerandom'
require 'base64'

class AdminSession
  attr_reader :userid, :password, :sessionid

  def initialize(userid, password)
    @userid = userid
    @password = password
    @sessionid = new_sessionid()
  end

  def new_sessionid()
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
  def initialize()
    @db = []
  end

  def new_session(userid, password)
    del_userid(userid)

    session = AdminSession.new(userid, password)
    return false unless session
    @db << session
  end

  def resume_session(sessionid)
    @db.find do |session|
      session.sessionid == sessionid
    end
  end

  def del_userid(userid)
    @db.delete_if do |session|
      session.userid == userid
    end
  end

  def del_session(sessionid)
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

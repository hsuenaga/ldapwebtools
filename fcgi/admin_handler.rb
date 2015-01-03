#!/usr/bin/env ruby
require 'rubygems'
require 'syslog'
require 'erb'
require 'cgi'
require 'uri'
include ERB::Util

#
# Base Class
#
class AdminHandler
  attr_reader :name
  attr_accessor :debug

  QUERY_ACTION_CODE = "submit"
  COOKIE_AUTH_TOKEN = "auth_token"

  class Context
    attr_reader :myname, :query
    attr_accessor :destination, :action, :guide, :debug

    def initialize(myname, query, action, session, guide)
      @myname = myname
      @query = query
      @session = session
      @destination = :login
      @action = action
      @guide = guide
      @cookie_issue = []
      @cookie_recv = {}
    end

    def sessionid()
      return nil unless @session
      @session.sessionid()
    end

    def userid()
      return nil unless @session
      @session.userid
    end

    def password()
      return nil unless @session
      @session.password
    end

    def new_cookie(cookie)
      @cookie_issue << cookie
    end

    def each_cookie(&block)
      @cookie_issue.each do |cookie|
        block.call(cookie)
      end
    end

    def flush_cookie()
      @cookie_issue = []
    end

    def new_session(db, userid, password)
      @session = db.new_session(userid, password)
      timeout = Time.now() + @session.timeout()
      cookie = CGI::Cookie.new({'name' => COOKIE_AUTH_TOKEN,
                                'value' => "#{@session}",
                                'expires' => timeout,
                                'domain' => @myname,
                                'path' => "/admin/",
                                'secure' => true})
      new_cookie(cookie)
      true
    end

    def close_session(db)
      return ture unless @session
      if @session.userid()
        db.del_userid(@session.userid())
      end
      true
    end
  end

  def initialize(ldap, session, action, template)
    @name = nil
    @ldap = ldap
    @template = nil
    @context = nil
    @debug = false

    #
    # external state presentation name mapping
    #
    @actionid_map = action.action_map
    @actioncode_map = action.action_map_inv

    #
    # session control
    #
    @sessiondb = session
    @session = nil 

    #
    # template
    #
    @template = ERB.new(File.open(template).read())

    #
    # context
    #
    @context = nil
  end

  def log(message, *args)
    if @debug
      printf(message, *args)
      printf("\n")
    else
      Syslog.info(message, *args)
    end
  end

  def log_err(message,*args)
    if @debug
      printf(message, *args)
      printf("\n")
    else
      Syslog.err(message, *args)
    end
  end

  def parse_actioncode(actioncode)
    @actioncode_map[actioncode]
  end

  def actioncode(actionid)
    @actionid_map[actionid]
  end

  def parse_subst(string, delim = ' ')
    return {} if string == nil || string == ""

    args = {}
    args_pair = string.split(delim)
    args_pair.each do |pair|
      keyvalue = pair.split('=', 2)
      key = URI.unescape(keyvalue[0])
      if keyvalue[1]
        value = URI.unescape(keyvalue[1])
      else
        value = ""
      end
      args[key] = value
    end

    args
  end

  def getquery(request)
    limit = 1024

    case request.env['REQUEST_METHOD']
    when /(GET|PUT)/
      rawstring = request.env['QUERY_STRING']
    when 'POST'
      lenstr = request.env['CONTENT_LENGTH']
      return {} unless lenstr
      len = lenstr.to_i()
      reutrn {} if len > limit
      rawstring = request.in.read(len)
    else
      rawstring = nil
    end
    return {} unless rawstring
    return {} if rawstring.size == 0
    rawstring = URI.unescape(rawstring)

    parse_subst(rawstring, '&')
  end

  def handle_request(request)
    # requested domain
    myname = request.env['HTTP_HOST']

    # parse query string
    query = getquery(request)

    # parse action
    action = @actioncode_map[query[QUERY_ACTION_CODE]]

    # parse cookie
    cookie_recv = parse_subst(request.env['HTTP_COOKIE'])

    # resume session
    session = @sessiondb.resume_session(cookie_recv[COOKIE_AUTH_TOKEN])

    @context = Context.new(myname, query, action, session, "")
  end

  def http_header(context)
    header = ""
    header += "Content-Type: text/html\r\n"
    context.each_cookie do |cookie|
      header += "Set-Cookie: #{cookie}\r\n"
      log("Cookie-Issue: %s", cookie)
    end
    header += "\r\n"
    context.flush_cookie()

    header
  end

  def reply_response(context)
    log("GUIDE: #{context.guide}")
    action = @actionid_map[context.action()]
    contents = ""
    if !@template
      return "ERROR: No Template for #{@name}.#{context.action()}"
    end
    log("NextHandler => #{@name}")
    contents += http_header(context)
    contents += @template.result(binding)
  end

  def finish()
    @context = nil
  end
end # class AdminHandler

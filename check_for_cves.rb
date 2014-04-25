# example script to display all active server instances
# where a given CVE was identified
# Eric Hoffmann <ehoffmann@cloudpassage.com>

require 'optparse'
require 'oauth2'
require 'rest-client'
require 'json'
require 'yaml'

# API helper class
class API
  def initialize (key_id, secret_key, host)
    client = OAuth2::Client.new(key_id, secret_key,
                  :site => "https://#{host}",
                  :token_url => '/oauth/access_token')
    token = client.client_credentials.get_token.token
    @base = "https://#{host}/v1"
    @header = {'Authorization' => "Bearer #{token}"}
  end
  def get(url)
    RestClient.get("#{@base}/#{url}", @header){|resp, req, res, &block|
    if (200..499).include? resp.code
      resp
    else
      resp.return!(req, res, &block)
    end
    }
  end
end

# pass in a single or list of CVEs to check for
options = {:cve => nil}
parser = OptionParser.new do |opts|
  opts.on('-c', '--cve ', 'single CVE or comma separated list') do |cve|
    options[:cve] = cve
  end
  msg = "usage: check_for_cves.rb --cve \"CVE-2014-0160,CVE-2014-1912\""
  opts.on('-h', '--help', msg) do
    puts opts
    exit
  end
end
parser.parse!

# setup the account specific API-Client key/secret and
# save these in a dot file like ~/.halo Reference the
# location as a ENV param instead of "hardcoding"
# them into this script (which may end up in a repo
# by mistake)
#
# the format of the yaml file ie ~/.halo
# halo-acct1:
#   key_id : XXXXXXX1
#   secret_key : XXXXXXXXXXXXXXXXXXXXXXXXXX1
#
# optionally, add a second, third etc. acct key/secret
# halo-acct2:
#   key_id : XXXXXXX2
#   secret_key : XXXXXXXXXXXXXXXXXXXXXXXXXX2
#
# and adding an additional grid param is supported as well
# halo-acct3:
#   key_id : XXXXXXX3
#   secret_key : XXXXXXXXXXXXXXXXXXXXXXXXXX3
#   grid : api.<unique>.cloudpassage.com
#
# don't forget to add and export HALO_API_KEY_FILE
# in your ~/.bash_profile Should look something like
# HALO_API_KEY_FILE="/home/ehoffmann/.halo"
# export HALO_API_KEY_FILE
begin
  api_keys = YAML.load_file("#{ENV['HALO_API_KEY_FILE']}")
  srv_counts = Hash.new()
rescue => e
  puts "[ERROR] loading api_keys"
  puts e
  exit
end

# setup a header for our output
puts "halo_account, hostname, connecting_ip_addr, platform, \
platform_version, pkg_name, pkg_version, cve"

# loop through each acct
api_keys.each do |acct, attrs|
  if attrs['grid'].nil? # set a default
    attrs['grid'] = 'api.cloudpassage.com'
  end
  # setup our api session
  @api = API.new(attrs['key_id'], attrs['secret_key'], attrs['grid'])

  # search for active servers
  resp = @api.get("/servers?state=active")
  data = JSON.parse(resp)

  # iterate through each server, grab its issues from
  # the last scheduled or manually launched scan
  srv_counts[acct] = data['servers'].length
  data['servers'].each do |srv|
    # srv['reported_fqdn'] is available too
    host = "#{acct}, #{srv['hostname']}, #{srv['connecting_ip_address']}"
    platform = "#{srv['platform']}, #{srv['platform_version']}"
    i = @api.get("/servers/#{srv['id']}/svm")
    d = JSON.parse(i)

    begin # only look at vulnerability issues
      d['scan']['findings'].each do |detail|
        # iterate through each CVE
        detail['cve_entries'].each do |cve|
          if options[:cve].downcase.include?(cve['cve_entry'].downcase) # opts from cmdline
            pkg = "#{detail['package_name']}, #{detail['package_version']}, #{cve['cve_entry']}"
            puts "#{host}, #{platform}, #{pkg}"
          end
        end
      end
    rescue => e
      # no vuln scan has completed
    end
  end
end
# describe how many servers and under which acct were checked
srv_counts.each do |acct, total|
  puts "Checked #{total} servers on #{acct} for #{options[:cve]}"
end

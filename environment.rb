require 'bundler'
Bundler.require(:default)
ROOT = File.dirname(__FILE__)
require 'tmpdir'

Dir[File.join(ROOT, 'garrison/lib/*.rb')].each do |file|
  require file
end

Dir[File.join(ROOT, 'garrison/checks/*.rb')].each do |file|
  require file
end

Garrison::Api.configure do |config|
  config.url = ENV['GARRISON_URL']
end

Garrison::Logging.info('Garrison Agent - Bundler Audit')

module Garrison
  module Checks
    @options = {}
    @options[:github_private_key_base64] = ENV['GARRISON_GITHUB_PRIVATE_KEY_BASE64']
    @options[:github_app_id] = ENV['GARRISON_GITHUB_APP_ID']
    @options[:github_exclude_repositories] = ENV['GARRISON_GITHUB_EXCLUDE_REPOS'] ? ENV['GARRISON_GITHUB_EXCLUDE_REPOS'].split(',') : nil
  end
end

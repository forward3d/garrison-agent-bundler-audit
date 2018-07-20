require 'bundler/audit/scanner'

module Garrison
  module Checks
    class CheckBundlerAudit < Check

      def settings
        self.source ||= 'bundler-audit'
        self.family ||= 'software'
        self.type   ||= 'security'
      end

      def perform
        update_bundle_audit
        if options[:github_private_key_base64]
          Octokit.auto_paginate = true

          Logging.info 'Logging into Github'
          jwt = JwtHelper.new_jwt_token(options[:github_private_key_base64], options[:github_app_id])
          client = Octokit::Client.new(bearer_token: jwt)
          installations = client.find_app_installations
          Logging.info "Found #{installations.count} app installations"
          installations.each do |installation|

            Logging.info "Logging into installation '#{installation.account.login}'"
            token = client.create_app_installation_access_token(installation.id)
            org = Octokit::Client.new(access_token: token.token)
            repositories = org.list_app_installation_repositories[:repositories]
            Logging.info "Found #{repositories.count} repositories"
            repositories.reject! { |repo| options[:github_exclude_repositories].include?(repo.full_name) } if options[:github_exclude_repositories]
            Logging.info "Found #{repositories.count} repositories after exclusions"

            repositories.each do |repo|

              Logging.info "#{repo.full_name} - Looking for Gemfile.lock files"
              begin
                search = org.search_code("filename:Gemfile.lock repo:#{repo.full_name}")
                Logging.debug org.rate_limit.inspect
              rescue Octokit::TooManyRequests
                Logging.warn "Octokit::TooManyRequests - Sleeping for #{org.rate_limit.resets_in}s"
                sleep org.rate_limit.resets_in + 1
                Logging.info 'Retrying request'
                retry
              end
              Logging.info "#{repo.full_name} - #{search[:total_count]} found"
              next if search[:total_count].zero?

              search[:items].each do |gemfile|
                Dir.mktmpdir(repo.full_name.tr('/', '-')) do |dir|
                  begin
                    gemfile = org.contents(repo.full_name, path: gemfile.path)
                    File.open(File.join(dir, 'Gemfile.lock'), 'w') { |f| f.write(Base64.decode64(gemfile[:content])) }
                    Logging.info "#{repo.full_name} - Scanning #{gemfile.path}"
                    scan_lock_file(repo, dir, gemfile)
                  rescue Octokit::NotFound
                    Logging.info "#{repo.full_name} - Skipping - Gemfile.lock not found"
                    next
                  end
                end
              end

            end
          end
        end
      end

      private

      def scan_lock_file(repo, dir, gemfile)
        scanner = Bundler::Audit::Scanner.new(dir)
        scanner.scan.each do |result|

          case result
          when Bundler::Audit::Scanner::InsecureSource

          when Bundler::Audit::Scanner::UnpatchedGem
            alert(
              name: 'Vulnerable Dependency',
              target: "#{repo.full_name}/#{gemfile.path}",
              detail: "#{result.gem.name}: #{result.advisory.id}",
              finding: result.advisory.to_h.to_json,
              note: result.advisory.description,
              external_severity: CveHelper.cvss_score_to_severity(result.advisory.cvss_v2),
              finding_id: "#{repo.full_name}-#{gemfile.path}-#{result.gem.name}-#{result.advisory.id}",
              urls: [
                {
                  name: 'Github Repository',
                  url: repo.html_url
                },
                {
                  name: 'Github Repository - Gemfile.lock',
                  url: gemfile.html_url
                },
                {
                  name: 'CVE Details',
                  url: "https://www.cvedetails.com/cve-details.php?cve_id=CVE-#{result.advisory.cve}"
                },
                {
                  name: 'NIST',
                  url: File.join('https://nvd.nist.gov/vuln/detail', "CVE-#{result.advisory.cve}")
                },
                {
                  name: 'Mitre',
                  url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-#{result.advisory.cve}"
                }
              ],
              key_values: [
                {
                  key: 'repo',
                  value: repo.full_name
                },
                {
                  key: 'cve',
                  value: "CVE-#{result.advisory.cve}"
                }
              ]
            )
          end
        end
      end

      def update_bundle_audit
        Logging.info 'Updating ruby-advisory-db'
        case Bundler::Audit::Database.update!(quiet: true)
        when true
          Logging.info 'Updated ruby-advisory-db'
        when false
          Logging.error 'Failed updating ruby-advisory-db!'
          exit 1
        when nil
          Logging.info 'Skipping updating ruby-advisory-db'
        end
      end

    end
  end
end

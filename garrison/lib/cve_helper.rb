module Garrison
  class CveHelper

    def self.cvss_score_to_severity(cvss_score)
      # https://nvd.nist.gov/vuln-metrics/cvss
      case cvss_score.to_f
      when 0.0..3.9
        'low'
      when 4.0..6.9
        'medium'
      when 7.0..10.0
        'high'
      else
        'info'
      end
    end

  end
end

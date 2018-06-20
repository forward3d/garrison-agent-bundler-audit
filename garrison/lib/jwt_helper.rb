module Garrison
  class JwtHelper

    def self.new_jwt_token(private_pem_encoded, github_app_id)
      # https://github.com/octokit/octokit.rb/issues/812
      private_pem = Base64.decode64(private_pem_encoded)
      private_key = OpenSSL::PKey::RSA.new(private_pem)
      payload = {
        iat: Time.now.to_i, # Issued at time.
        exp: Time.now.to_i + (10 * 60), # JWT expiration time.
        iss: github_app_id.to_i # Integration's GitHub identifier.
      }
      JWT.encode(payload, private_key, 'RS256')
    end

  end
end

# Copyright 2023 Google, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.require "time"

require "googleauth/base_client"
require "googleauth/helpers/connection"
require "googleauth/oauth2/sts_client"

module Google
	# Module Auth provides classes that provide Google-specific authorization
  # used to access Google APIs.
  module Auth
    module ExternalAccount
    	class BaseCredentials
    		extend CredentialsLoader
    		include BaseClient
    		include Helpers::Connection

    		attr_reader :project_id
    		attr_reader :quota_project_id
    		attr_reader :expires_at
    		attr_accessor :access_token

    		AWS_SUBJECT_TOKEN_TYPE = "urn:ietf:params:aws:token-type:aws4_request".freeze
    		AWS_SUBJECT_TOKEN_INVALID = "aws is the only currently supported external account type".freeze

    		TOKEN_URL_PATTERNS = [
    		  /^[^.\s\/\\]+\.sts(?:\.mtls)?\.googleapis\.com$/.freeze,
    		  /^sts(?:\.mtls)?\.googleapis\.com$/.freeze,
    		  /^sts\.[^.\s\/\\]+(?:\.mtls)?\.googleapis\.com$/.freeze,
    		  /^[^.\s\/\\]+-sts(?:\.mtls)?\.googleapis\.com$/.freeze,
    		  /^sts-[^.\s\/\\]+\.p(?:\.mtls)?\.googleapis\.com$/.freeze
    		].freeze

    		SERVICE_ACCOUNT_IMPERSONATION_URL_PATTERNS = [
    		  /^[^.\s\/\\]+\.iamcredentials\.googleapis\.com$/.freeze,
    		  /^iamcredentials\.googleapis\.com$/.freeze,
    		  /^iamcredentials\.[^.\s\/\\]+\.googleapis\.com$/.freeze,
    		  /^[^.\s\/\\]+-iamcredentials\.googleapis\.com$/.freeze,
    		  /^iamcredentials-[^.\s\/\\]+\.p\.googleapis\.com$/.freeze
    		].freeze

    		def expires_within? seconds
    		  # This method is needed for BaseClient
    		  @expires_at && @expires_at - Time.now.utc < seconds
    		end

    		def expires_at= new_expires_at
    		  @expires_at = normalize_timestamp new_expires_at
    		end

    		# Create a ExternalAccount::Credentials
    		#
    		# @param json_key_io [IO] an IO from which the JSON key can be read
    		# @param scope [string|array|nil] the scope(s) to access
    		def self.make_creds options = {}
    		  json_key_io, scope = options.values_at :json_key_io, :scope

    		  raise "A json file is required for external account credentials." unless json_key_io
    		  user_creds = read_json_key json_key_io

    		  raise "The provided token URL is invalid." unless is_token_url_valid? user_creds["token_url"]
    		  unless is_service_account_impersonation_url_valid? user_creds["service_account_impersonation_url"]
    		    raise "The provided service account impersonation url is invalid."
    		  end

    		  # TODO: check for other External Account Credential types. Currently only AWS is supported.
    		  raise AWS_SUBJECT_TOKEN_INVALID unless user_creds["subject_token_type"] == AWS_SUBJECT_TOKEN_TYPE

    		  Google::Auth::ExternalAccount::AwsCredentials.new(
    		    audience: user_creds["audience"],
    		    scope: scope,
    		    subject_token_type: user_creds["subject_token_type"],
    		    token_url: user_creds["token_url"],
    		    credential_source: user_creds["credential_source"],
    		    service_account_impersonation_url: user_creds["service_account_impersonation_url"]
    		  )
    		end

    		# Reads the required fields from the JSON.
    		def self.read_json_key json_key_io
    		  json_key = MultiJson.load json_key_io.read
    		  wanted = [
    		    "audience", "subject_token_type", "token_url", "credential_source"
    		  ]
    		  wanted.each do |key|
    		    raise "the json is missing the #{key} field" unless json_key.key? key
    		  end
    		  json_key
    		end

    		def self.is_valid_url? url, valid_hostnames
    		  begin
    		    uri = URI(url)
    		  rescue URI::InvalidURIError, ArgumentError
    		    return false
    		  end

    		  return false unless uri.scheme == "https"

    		  valid_hostnames.any? { |hostname| hostname =~ uri.host }
    		end

    		def self.is_token_url_valid? url
    		  is_valid_url? url, TOKEN_URL_PATTERNS
    		end

    		def self.is_service_account_impersonation_url_valid? url
    		  !url or is_valid_url? url, SERVICE_ACCOUNT_IMPERSONATION_URL_PATTERNS
    		end

    		def fetch_access_token! _options = {}
    		  # This method is needed for BaseClient
    		  response = exchange_token

    		  if @service_account_impersonation_url
    		    impersonated_response = get_impersonated_access_token response["access_token"]
    		    self.expires_at = impersonated_response["expireTime"]
    		    self.access_token = impersonated_response["accessToken"]
    		  else
    		    # Extract the expiration time in seconds from the response and calculate the actual expiration time
    		    # and then save that to the expiry variable.
    		    self.expires_at = Time.now.utc + response["expires_in"].to_i
    		    self.access_token = response["access_token"]
    		  end

    		  notify_refresh_listeners
    		end

    		private

    		STS_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange".freeze
    		STS_REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token".freeze
    		IAM_SCOPE = [
    		  "https://www.googleapis.com/auth/iam".freeze
    		].freeze

    		def base_setup options
    		  self.default_connection = options[:connection]

    		  @audience = options[:audience]
    		  @scope = options[:scope] || IAM_SCOPE
    		  @subject_token_type = options[:subject_token_type]
    		  @token_url = options[:token_url]
    		  @service_account_impersonation_url = options[:service_account_impersonation_url]

    		  @expires_at = nil
    		  @access_token = nil

    		  @sts_client = Google::Auth::OAuth2::STSClient.new(
    		    token_exchange_endpoint: @token_url,
    		    connection: default_connection
    		  )
    		end

    		def token_type
    		  # This method is needed for BaseClient
    		  :access_token
    		end

    		def exchange_token
    		  @sts_client.exchange_token(
    		    audience: @audience,
    		    grant_type: STS_GRANT_TYPE,
    		    subject_token: retrieve_subject_token!,
    		    subject_token_type: @subject_token_type,
    		    scopes: @service_account_impersonation_url ? IAM_SCOPE : @scope,
    		    requested_token_type: STS_REQUESTED_TOKEN_TYPE
    		  )
    		end

    		def retrieve_subject_token!
    		  raise NotImplementedError
    		end

    		def normalize_timestamp time
    		  case time
    		  when NilClass
    		    nil
    		  when Time
    		    time
    		  when String
    		    Time.parse time
    		  else
    		    raise "Invalid time value #{time}"
    		  end
    		end

    		def get_impersonated_access_token token, _options = {}
    		  response = connection.post @service_account_impersonation_url do |req|
    		    req.headers["Authorization"] = "Bearer #{token}"
    		    req.headers["Content-Type"] = "application/json"
    		    req.body = MultiJson.dump({ scope: @scope })
    		  end

    		  if response.status != 200
    		    raise "Service account impersonation failed with status #{response.status}"
    		  end

    		  MultiJson.load response.body
    		end
    	end
    end
  end
end
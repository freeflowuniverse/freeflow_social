require "base64"

module OmniAuth
  module Strategies
    class Threefold
      include OmniAuth::Strategy

      args [:key, :scope, :callback_url, :server_url, :kyc_url]

      option :key, nil
      option :scope, [:user, :email]

      option :callback_url, nil
      option :server_url, 'https://login.threefold.me'
      option :kyc_url, 'https://openkyc.live/verification/verify-sei'

      attr_accessor :data

      def signing_key
        RbNaCl::SigningKey.new(Base64.decode64(options[:key]))
      end

      def get_user_public_key(double_name)
        resp = Net::HTTP.get_response(URI("#{options[:server_url]}/api/users/#{double_name}"))
        if resp.kind_of?(Net::HTTPOK)
          return JSON.parse(resp.body)["publicKey"]
        end

        raise resp.body
      end

      def verify_email(sei)
        resp = Net::HTTP.post(URI(options[:kyc_url]), { "signedEmailIdentifier": sei }.to_json, { "Content-Type" => "application/json" })
        unless resp.kind_of?(Net::HTTPOK)
          raise "email is not verified"
        end
      end

      def validate_fields(data, fields)
        fields.each do |field|
          unless data.key?(field)
            raise "missing '#{field}'"
          end
        end
      end

      # decrypt verified data
      # @param verify_key [VerifyKey] used to verify this data
      # @param data [Hash] e.g. {data => {"nonce" => "...", "ciphertext" => "..."}}
      #
      # @return [Hash] containing scope fields e.g. email and username
      def decrypt_verified_data(verify_key, data)
        nonce = Base64.strict_decode64(data["data"]["nonce"])
        ciphertext = Base64.strict_decode64(data["data"]["ciphertext"])

        private_key = signing_key.to_curve25519_private_key
        public_key = verify_key.to_curve25519_public_key
        box = RbNaCl::Box.new(public_key, private_key)
        decrypted = box.decrypt(nonce, ciphertext)
        JSON.parse(decrypted)
      end

      # verify login attempt
      # @param attempt [Hash] must containing `doubleName` and `signedAttempt`
      #
      # @raise in case verifying the login attempt failed
      #
      # @return [Hash] containing user info as `email` and `username`
      def verify(attempt)
        validate_fields(attempt, ["signedAttempt", "doubleName"])

        signed_data = Base64.strict_decode64(attempt["signedAttempt"])
        double_name = attempt["doubleName"]
        public_key = get_user_public_key(double_name)
        verify_key = RbNaCl::VerifyKey.new(Base64.strict_decode64(public_key))

        # signed_data have the signature attached, so, split them
        signature, signed_data = signed_data[0...verify_key.signature_bytes], signed_data[verify_key.signature_bytes..-1]
        # will raise an error if verification failed
        verify_key.verify(signature, signed_data)
        verified_data = JSON.parse(signed_data)
        validate_fields(verified_data, ["data", "signedState", "doubleName"])

        state = verified_data["signedState"]
        if state != session[:auth_state]
          raise "state has been changed"
        end

        decrypted = decrypt_verified_data(verify_key, verified_data)
        validate_fields(decrypted, ["email"])
        verify_email(decrypted["email"]["sei"])
        { email: decrypted["email"]["email"], user: double_name }
      end

      def callback_url
        options[:callback_url] || callback_path
      end

      def request_phase
        state = SecureRandom.uuid.gsub("-", "")
        scope = options[:scope].to_h {|field| [field, true]}
        params = {
          :appid => request.host_with_port,
          :scope => JSON.generate(scope),
          :publickey => Base64.strict_encode64(signing_key.verify_key.to_curve25519_public_key.to_s),
          :redirecturl => callback_url,
          :state => state,
        }

        session[:auth_state] = params[:state]
        redirect "#{options[:server_url]}?#{params.to_query}"
      end

      def callback_phase
        begin
          attempt = JSON.parse(request.params["signedAttempt"])
          @data = verify(attempt)
        rescue => err
          fail!(:error, err)
        end

        super
      end

      def username
        data[:user].chomp(".3bot")
      end

      def email
        data[:email]
      end

      uid do
        username
      end

      info do
        {
          :name => username,
          :nickname => username,
          :email => email,
          :verified => true
         }
      end

    end
  end
end

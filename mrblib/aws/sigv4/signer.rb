module AWS
  module SigV4
    class Signer
      def initialize(access_key_id:, secret_access_key:, region:)
        @access_key_id = access_key_id
        @secret_access_key = secret_access_key
        @region = region.to_s
      end

      def sign(service:, time: Time.now, method:, path:, query: nil, headers: {}, body: nil)
        time = time.utc if time.kind_of?(Time)
        headers_str = headers.kind_of?(String) ? headers :
                      headers.map { |k, v| "#{k}: #{v}" }.join("\r\n")
        # ensure blank line at end of headers string
        headers_str += "\r\n" until headers_str["\r\n\r\n"]
        generate_signature access_key_id: @access_key_id,
                           secret_access_key: @secret_access_key,
                           region: @region,
                           service: service.to_s,
                           time: time.kind_of?(String) ? time :
                                 "%04d%02d%02dT%02d%02d%02dZ" % [
                                    time.year, time.month, time.day,
                                    time.hour, time.min,   time.sec
                                 ],
                           request_method: method.to_s.upcase,
                           request_path: path,
                           request_query: query.to_s,
                           request_headers: headers_str,
                           request_body: body.to_s
      end
    end
  end
end

assert 'sigv4' do
  signer = AWS::SigV4::Signer.new access_key_id: 'AKIAIOSFODNN7EXAMPLE',
                                  secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
                                  region: 'us-east-1'
  time = Time.utc(2021, 8, 11, 0, 15, 58, 0)
  headers = {
    'Host' => 'iam.amazonaws.com',
    'Content-Type' => 'application/x-www-form-urlencoded; charset=utf-8',
    'X-Amz-Date' => '20210811T001558Z'
  }
  result = signer.sign(service: :iam,
                       time: time,
                       method: :get,
                       query: 'Action=ListUsers&Version=2010-05-08',
                       path: '/',
                       headers: headers)
  assert_equal "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20210811/us-east-1/iam/aws4_request, "+
               "SignedHeaders=content-type;host;x-amz-date, "+
               "Signature=20fdb62349e7104f9ce4184a444fedfbd19e40a5e31d57d433689c5a5138fa99",
               result
end

assert 'big data does not fail with memory error' do
  # if an amzn security token is included, that's pretty large and exhausts
  # the default amount of memory. This test ensures we compile with enough
  # memory allocated to support the token's inclusion.
  args = {
    :service=>"execute-api",
    :time=>Time.now,
    :method=>:post,
    :path=>"/path/to/service",
    :headers=>{"content-length"=>"1016",
               "host"=>"www.customservice.com",
               "accept"=>"application/json",
               "user-agent"=>"my user agent",
               "connection"=>"keep-alive",
               "x-amzn-iot-thingname"=>"123456789012",
               "x-amz-security-token"=>"FAKE" * 243,
               "content-type"=>"application/json"},
     :body=>"also large" * 114
   }
  signer = AWS::SigV4::Signer.new access_key_id: 'AKIAIOSFODNN7EXAMPLE',
                                  secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
                                  region: 'us-east-1'
  result = signer.sign(**args)
  # didn't raise an error? all good
  assert_true true
end
